import { createApp } from 'vue';
import { createPinia } from 'pinia';
import App from './App.vue';
import { router } from './router';
import { useTheme } from './composables/useTheme';
import './styles/main.css';

const app = createApp(App);

app.use(createPinia());
app.use(router);

// 主题必须在挂载前应用，否则会先按默认令牌渲染一帧再跳变
useTheme();

app.mount('#app');
