//! 网卡拓扑采集：把多个 Win32 数据源汇聚成一份 [`TopologySnapshot`]。
//!
//! 数据源分工（刻意这样切，是为了让每一路的失败都可独立降级）：
//! - `GetIfTable2`        → LUID / 网线 MAC / 别名 / 类型 / 运营状态（稳定、开销小）
//! - `GetAdaptersAddresses` → 本机 IPv4 / DHCP 服务器
//! - `GetIpForwardTable2` → 网关 + 默认出口裁决
//! - WLAN AutoConfig API  → SSID（失败即降级为 None）
//!
//! 全部为**只读**调用，本模块不修改任何系统状态。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ptr;

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKET_ADDRESS};

use crate::error::{check, SenseError, Win32Error};
use crate::fingerprint::compute_fingerprint;
use crate::model::{InterfaceInfo, MacAddress, OperStatus, TopologySnapshot};
use crate::route::RouteRow;

/// 由 `GetAdaptersAddresses` 汇总出的 per-interface IPv4 侧信息。
#[derive(Debug, Default, Clone)]
struct AdapterIpInfo {
    ipv4: Vec<Ipv4Addr>,
    dhcp_server: Option<Ipv4Addr>,
}

/// 采集一次完整拓扑快照。
pub fn snapshot() -> Result<TopologySnapshot, SenseError> {
    let ifaces = enumerate_interfaces()?;
    let routes = crate::route::ipv4_routes()?;

    // 默认出口裁决：只在默认路由中挑，且**优先挑接口当前处于 Up 的那条**。
    // 若所有默认路由都落在 Down 接口（例如拔线后残留的路由），才退回纯 Metric 最小。
    let default_egress_luid = pick_default_egress(&routes, &ifaces);

    let mut interfaces = attach_route_info(ifaces, &routes);

    let fingerprint = compute_fingerprint(&interfaces);
    interfaces.sort_by(|a, b| a.luid.cmp(&b.luid).then_with(|| a.alias.cmp(&b.alias)));

    Ok(TopologySnapshot {
        interfaces,
        default_egress_luid,
        fingerprint,
    })
}

/// 枚举全部网络接口（含 Down 状态，以便上层判断"新插/拔出"）。
pub fn enumerate_interfaces() -> Result<Vec<InterfaceInfo>, SenseError> {
    unsafe {
        let base_rows = if_table_rows()?;
        let ip_map = adapter_ip_map().unwrap_or_default();
        // SSID 采集失败是可接受的降级：标记为 None 而不是让整次拓扑采集失败
        let ssid_by_guid: HashMap<String, String> = crate::wifi::connected_ssids()
            .unwrap_or_default()
            .into_iter()
            .map(|(guid, ssid)| (format!("{:?}", guid), ssid))
            .collect();

        let mut out = Vec::with_capacity(base_rows.len());
        for row in base_rows {
            let guid_key = format!("{:?}", row.InterfaceGuid);
            let info = ip_map.get(&row.InterfaceIndex).cloned().unwrap_or_default();

            out.push(InterfaceInfo {
                luid: row.InterfaceLuid.Value,
                index: row.InterfaceIndex,
                alias: wide_trim(&row.Alias),
                description: wide_trim(&row.Description),
                mac: mac_from(&row.PhysicalAddress, row.PhysicalAddressLength),
                if_type: row.Type,
                oper_status: map_oper_status(row.OperStatus.0),
                ipv4: info.ipv4,
                gateway: Vec::new(), // 后一步由路由表填充
                dhcp_server: info.dhcp_server,
                ssid: ssid_by_guid.get(&guid_key).cloned(),
            });
        }
        Ok(out)
    }
}

/// 默认出口裁决：**优先"默认路由 ∧ 接口 Up"**，再按**合成度量**最小。
/// 返回 0 表示没有任何 IPv4 默认路由。
///
/// 两点必须注意：
/// 1. 比较的是 [`RouteRow::effective_metric`]（接口度量 + 路由度量偏移），
///    绝不能只比 `route_metric` —— 后者在自动度量下恒为 0，会把出口判错。
/// 2. 只在"接口 Up"的默认路由里挑。拔线/停用后残留的默认路由会让裁决
///    指向一张已经不通的网卡；只有全都不通时才退回不设限的最优选。
fn pick_default_egress(routes: &[RouteRow], ifaces: &[InterfaceInfo]) -> u64 {
    let is_up = |luid: u64| ifaces.iter().any(|i| i.luid == luid && i.is_up());
    let default_routes = || routes.iter().filter(|r| r.dest_prefix_len == 0);

    // 先按"接口 Up"过滤后取最优；全都不通时再退回全体最优
    let mut candidates: Vec<RouteRow> = default_routes()
        .filter(|r| is_up(r.interface_luid))
        .cloned()
        .collect();
    if candidates.is_empty() {
        candidates = default_routes().cloned().collect();
    }

    crate::route::pick_best(candidates)
        .map(|r| r.interface_luid)
        .unwrap_or(0)
}

/// 从 `GetIfTable2` 取回全部 `MIB_IF_ROW2`。
unsafe fn if_table_rows() -> Result<Vec<MIB_IF_ROW2>, SenseError> {
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    let code: WIN32_ERROR = GetIfTable2(&mut table);
    check("GetIfTable2", code.0)?;
    if table.is_null() {
        return Err(SenseError::Malformed {
            op: "GetIfTable2",
            detail: "返回空表指针".into(),
        });
    }
    let n = (*table).NumEntries as usize;
    let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n).to_vec();
    FreeMibTable(table as *const core::ffi::c_void);
    Ok(rows)
}

/// 用 `GetAdaptersAddresses` 收集 per-index 的 IPv4 / DHCP 信息。
unsafe fn adapter_ip_map() -> Result<HashMap<u32, AdapterIpInfo>, SenseError> {
    let mut size: u32 = 0;
    let flags: GET_ADAPTERS_ADDRESSES_FLAGS = core::mem::zeroed();

    // 第一次调用：取所需缓冲区大小（预期返回 ERROR_BUFFER_OVERFLOW）
    let rc = GetAdaptersAddresses(AF_INET.0 as u32, flags, None, None, &mut size);

    // 除 buffer overflow 外，任何非 "NO_DATA" 的失败都要上报
    if rc != 0 && rc != 111 && size == 0 {
        // ERROR_BUFFER_OVERFLOW = 111, ERROR_NO_DATA = 232
        return Err(SenseError::Os {
            op: "GetAdaptersAddresses(probe)",
            code: Win32Error(rc),
        });
    }
    if size == 0 {
        return Ok(HashMap::new());
    }

    let mut buf = vec![0u8; size as usize];
    let rc = GetAdaptersAddresses(
        AF_INET.0 as u32,
        flags,
        None,
        Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
        &mut size,
    );
    check("GetAdaptersAddresses", rc)?;

    let mut map: HashMap<u32, AdapterIpInfo> = HashMap::new();
    let mut cur: *const IP_ADAPTER_ADDRESSES_LH = buf.as_ptr() as *const _;

    while !cur.is_null() {
        let a = &*cur;
        let mut entry = AdapterIpInfo {
            dhcp_server: socket_address_v4(&a.Dhcpv4Server),
            ..Default::default()
        };

        let mut uc = a.FirstUnicastAddress;
        while !uc.is_null() {
            if let Some(ip) = socket_address_v4(&(*uc).Address) {
                entry.ipv4.push(ip);
            }
            uc = (*uc).Next;
        }
        entry.ipv4.sort();

        // IP_ADAPTER_ADDRESSES_LH 把 Length/IfIndex 放在匿名 union 里，
        // windows-rs 展开为 Anonymous1.Anonymous.IfIndex
        map.insert(a.Anonymous1.Anonymous.IfIndex, entry);
        cur = a.Next;
    }

    Ok(map)
}

/// 把路由表中的网关归并回各接口，并据此判定角色线索。
fn attach_route_info(mut ifaces: Vec<InterfaceInfo>, routes: &[RouteRow]) -> Vec<InterfaceInfo> {
    for iface in ifaces.iter_mut() {
        let gws: Vec<Ipv4Addr> = routes
            .iter()
            .filter(|r| r.interface_luid == iface.luid && r.interface_index == iface.index)
            .filter_map(|r| r.next_hop)
            // 0.0.0.0 表示"直连/无下一跳"，不是真正的网关，须剔除
            .filter(|ip| !ip.is_unspecified())
            .collect();
        iface.gateway = dedup(gws);
    }
    ifaces
}

fn dedup(mut v: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    v.sort();
    v.dedup();
    v
}

/// 从 `SOCKET_ADDRESS` 取 IPv4（同样走稳定内存布局，避开 union 字段命名差异）。
unsafe fn socket_address_v4(sa: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    let p = sa.lpSockaddr as *const u8;
    let family = u16::from_ne_bytes([*p, *p.add(1)]);
    if family != AF_INET.0 {
        return None;
    }
    Some(Ipv4Addr::new(*p.add(4), *p.add(5), *p.add(6), *p.add(7)))
}

/// 定长宽字符数组 → 截断到首个 NUL 的字符串。
fn wide_trim(arr: &[u16]) -> String {
    let end = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    String::from_utf16_lossy(&arr[..end])
}

/// 取 MAC：仅当实际长度不小于 6 时成立（回环等无 MAC 接口为 None）。
fn mac_from(bytes: &[u8], len: u32) -> Option<MacAddress> {
    let len = len as usize;
    if len >= 6 && bytes.len() >= 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&bytes[..6]);
        Some(MacAddress(m))
    } else {
        None
    }
}

/// 映射 `IF_OPER_STATUS`：刻意只比较原始整数值（1..=7），
/// 这样就不必为了命名这些常量而额外启用 `Win32_NetworkManagement_Ndis` feature。
fn map_oper_status(raw: i32) -> OperStatus {
    match raw {
        1 => OperStatus::Up,
        2 => OperStatus::Down,
        3 => OperStatus::Testing,
        5 => OperStatus::Dormant,
        6 => OperStatus::NotPresent,
        7 => OperStatus::LowerLayerDown,
        _ => OperStatus::Unknown, // 0 与 4 都是 Unknown
    }
}
