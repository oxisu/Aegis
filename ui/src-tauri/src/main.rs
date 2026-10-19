//! 外壳入口。逻辑全在 [`aegis_console`] 里，这里只调一下——
//! 放逻辑在 lib 里是为了能写单测（端点解析、token 解析都不需要起窗口）。

// 发布版不弹控制台窗口。⚠ 调试版**保留**：外壳连不上守护进程时，
// 控制台是唯一的线索来源——那条窗口没了，界面上就只剩一句"未连接"。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    aegis_console::run()
}
