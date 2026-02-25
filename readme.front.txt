/* Подключение базовых стилей Tailwind CSS (версия 4 использует такой синтаксис) */
@import "tailwindcss";
/* Подключение плагина для удобных CSS-анимаций */
@import "tw-animate-css";

/* Определение кастомного варианта для темной темы.
  Позволяет использовать префикс `dark:` в классах Tailwind 
  (например, `dark:bg-black`), если у родительского элемента есть класс `.dark`.
*/
@custom-variant dark (&:is(.dark *));

/* Глобальные CSS-переменные для светлой темы.
  Здесь используется цветовое пространство `oklch`, которое обеспечивает 
  более естественное восприятие цветов человеческим глазом.
*/
:root {
  /* Основные цвета фона и текста */
  --background: oklch(0.97 0.006 95); /* Мягкий серый фон */
  --foreground: oklch(0.3 0 0);       /* Темно-серый текст */
  
  /* Цвета для карточек (Card) */
  --card: oklch(1 0 0);               /* Белый фон карточки */
  --card-foreground: oklch(0.3 0 0);  /* Цвет текста внутри карточки */
  
  /* Цвета для всплывающих окон (Popover, Dropdown и т.д.) */
  --popover: oklch(1 0 0);
  --popover-foreground: oklch(0.3 0 0);
  
  /* Основной акцентный цвет бренда (Primary) */
  --primary: oklch(0.6 0.22 267);     /* Насыщенный фиолетовый/синий */
  --primary-foreground: oklch(1 0 0); /* Текст на основном фоне (белый) */
  
  /* Вторичный цвет (Secondary) */
  --secondary: oklch(0.97 0.006 95);
  --secondary-foreground: oklch(0.3 0 0);
  
  /* Приглушенные цвета (для неактивных элементов или второстепенного текста) */
  --muted: oklch(0.965 0.004 95);
  --muted-foreground: oklch(0.52 0 0);
  
  /* Дополнительный акцентный цвет (Accent) */
  --accent: oklch(0.67 0.17 268);
  --accent-foreground: oklch(1 0 0);
  
  /* Цвет для ошибок и деструктивных действий (Удалить, Очистить) */
  --destructive: oklch(0.6 0.24 27);  /* Красный */
  --destructive-foreground: oklch(1 0 0);
  
  /* Цвета границ, полей ввода и колец фокуса */
  --border: oklch(0.9 0 0);
  --input: oklch(0.95 0.003 95);
  --ring: oklch(0.52 0.14 165);       /* Цвет обводки при фокусе (например, зеленый/бирюзовый) */
  
  /* Палитра для графиков и диаграмм */
  --chart-1: oklch(0.646 0.222 41.116);
  --chart-2: oklch(0.6 0.118 184.704);
  --chart-3: oklch(0.828 0.189 84.429);
  --chart-4: oklch(0.769 0.188 70.08);
  --chart-5: oklch(0.577 0.245 27.325);
  
  /* Базовый радиус скругления для компонентов (10px) */
  --radius: 0.625rem;
  
  /* Цветовая схема для боковой панели (Sidebar) */
  --sidebar: oklch(0.98 0.004 95);
  --sidebar-foreground: oklch(0.3 0 0);
  --sidebar-primary: oklch(0.52 0.15 165);
  --sidebar-primary-foreground: oklch(1 0 0);
  --sidebar-accent: oklch(0.965 0.004 95);
  --sidebar-accent-foreground: oklch(0.3 0 0);
  --sidebar-border: oklch(0.9 0 0);
  --sidebar-ring: oklch(0.52 0.15 165);

  /* Переменные для интеграции с цветами Telegram Web App */
  --telegram-bg: var(--background);
  --telegram-text: var(--foreground);
  --telegram-button: var(--primary);
}

/* Переопределение переменных для темной темы.
  Эти цвета применяются автоматически, если на теге <html> или <body> есть класс "dark".
*/
.dark {
  --background: oklch(0.145 0 0);     /* Темный, почти черный фон */
  --foreground: oklch(0.985 0 0);     /* Светло-серый/белый текст */
  
  --card: oklch(0.205 0 0);           /* Фон карточек чуть светлее общего фона */
  --card-foreground: oklch(0.985 0 0);
  
  --popover: oklch(0.205 0 0);
  --popover-foreground: oklch(0.985 0 0);
  
  --primary: oklch(0.628 0.199 267.799);
  --primary-foreground: oklch(0.145 0 0); /* Темный текст на светлом акцентном фоне */
  
  --secondary: oklch(0.269 0 0);
  --secondary-foreground: oklch(0.985 0 0);
  
  --muted: oklch(0.269 0 0);
  --muted-foreground: oklch(0.708 0 0);
  
  --accent: oklch(0.676 0.17 269.53);
  --accent-foreground: oklch(0.145 0 0);
  
  --destructive: oklch(0.396 0.141 25.723);
  --destructive-foreground: oklch(0.985 0 0);
  
  --border: oklch(0.269 0 0);
  --input: oklch(0.269 0 0);
  --ring: oklch(0.576 0.148 164.988);
  
  /* Графики в темной теме */
  --chart-1: oklch(0.488 0.243 264.376);
  --chart-2: oklch(0.696 0.17 162.48);
  --chart-3: oklch(0.769 0.188 70.08);
  --chart-4: oklch(0.627 0.265 303.9);
  --chart-5: oklch(0.645 0.246 16.439);
  
  /* Боковая панель в темной теме */
  --sidebar: oklch(0.205 0 0);
  --sidebar-foreground: oklch(0.985 0 0);
  --sidebar-primary: oklch(0.576 0.148 164.988);
  --sidebar-primary-foreground: oklch(0.145 0 0);
  --sidebar-accent: oklch(0.269 0 0);
  --sidebar-accent-foreground: oklch(0.985 0 0);
  --sidebar-border: oklch(0.269 0 0);
  --sidebar-ring: oklch(0.576 0.148 164.988);
}

/* Связывание наших CSS-переменных с утилитарными классами Tailwind 4.
  Это позволяет писать `bg-primary`, `text-muted-foreground`, `rounded-lg` и т.д.
*/
@theme inline {
  --font-sans: var(--font-geist-sans); /* Шрифт без засечек по умолчанию */
  --font-mono: var(--font-geist-mono); /* Моноширинный шрифт */
  
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  
  --color-destructive: var(--destructive);
  --color-destructive-foreground: var(--destructive-foreground);
  
  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);
  
  --color-chart-1: var(--chart-1);
  --color-chart-2: var(--chart-2);
  --color-chart-3: var(--chart-3);
  --color-chart-4: var(--chart-4);
  --color-chart-5: var(--chart-5);
  
  /* Вычисление радиусов на основе базовой переменной --radius */
  --radius-sm: calc(var(--radius) - 4px);
  --radius-md: calc(var(--radius) - 2px);
  --radius-lg: var(--radius);
  --radius-xl: calc(var(--radius) + 4px);
  
  --color-sidebar: var(--sidebar);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-primary: var(--sidebar-primary);
  --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
  --color-sidebar-accent: var(--sidebar-accent);
  --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sidebar-ring: var(--sidebar-ring);
}

/* Слой "base" (Базовые стили) - применяется к стандартным HTML-тегам.
*/
@layer base {
  * {
    /* Всем элементам по умолчанию задаем цвет рамки и полупрозрачный цвет фокуса */
    @apply border-border outline-ring/50;
  }
  
  body {
    /* Задаем фон и цвет текста для всего приложения */
    @apply bg-background text-foreground;
    
    /* Улучшение сглаживания шрифтов в браузерах WebKit и MacOS */
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
    -webkit-text-size-adjust: 100%;
    position: relative;
    
    /* Красивый градиентный фон для светлой темы */
    background: linear-gradient(135deg, 
      oklch(0.97 0.006 95) 0%, 
      oklch(0.98 0.008 200) 50%, 
      oklch(0.97 0.006 95) 100%);
  }
  
  /* Градиентный фон для темной темы */
  .dark body {
    background: linear-gradient(135deg, 
      oklch(0.145 0 0) 0%, 
      oklch(0.15 0.01 240) 50%, 
      oklch(0.145 0 0) 100%);
  }

  /* Плавная прокрутка для якорей на странице */
  html {
    scroll-behavior: smooth;
  }

  /* Стиль выделения элементов при навигации с клавиатуры (Tab) */
  :focus-visible {
    @apply outline-2 outline-offset-2 outline-ring;
  }

  /* --- Кастомизация скроллбара (полосы прокрутки) --- */
  ::-webkit-scrollbar {
    width: 6px; /* Тонкий скроллбар */
  }
  ::-webkit-scrollbar-track {
    @apply bg-muted; /* Цвет дорожки */
  }
  ::-webkit-scrollbar-thumb {
    @apply bg-muted-foreground/30 rounded-full; /* Цвет самого ползунка и скругление */
  }
  ::-webkit-scrollbar-thumb:hover {
    @apply bg-muted-foreground/50; /* Ползунок темнеет при наведении */
  }
}

/* Слой "utilities" - создание собственных классов-помощников.
  В основном используется для создания классов анимаций на основе @keyframes.
*/
@layer utilities {
  .animate-fade-in {
    animation: fadeIn 0.3s ease-in-out;
  }
  .animate-slide-up {
    animation: slideUp 0.3s ease-out;
  }
  .animate-scale-in {
    animation: scaleIn 0.2s ease-out;
  }
  .animate-collapsible-down {
    animation: collapsibleDown 0.2s ease-out;
  }
  .animate-collapsible-up {
    animation: collapsibleUp 0.2s ease-out;
  }
}

/* --- Определение самих анимаций (Keyframes) --- */

/* Плавное появление (из прозрачного в видимое) */
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* Всплытие снизу вверх с плавным появлением (отлично для модалок или карточек) */
@keyframes slideUp {
  from { transform: translateY(10px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

/* Увеличение масштаба (отлично для всплывающих подсказок или диалогов) */
@keyframes scaleIn {
  from { transform: scale(0.95); opacity: 0; }
  to { transform: scale(1); opacity: 1; }
}

/* Раскрытие аккордеона или выпадающего списка вниз */
@keyframes collapsibleDown {
  from { height: 0; opacity: 0; }
  to { height: var(--radix-collapsible-content-height); opacity: 1; }
}

/* Скрытие аккордеона или выпадающего списка (схлопывание вверх) */
@keyframes collapsibleUp {
  from { height: var(--radix-collapsible-content-height); opacity: 1; }
  to { height: 0; opacity: 0; }
}

/* Эффект падающего снега (вероятно используется в компоненте новогодней темы snow-effect.tsx) */
@keyframes snowfall {
  0% { transform: translateY(-100px) rotate(0deg); }
  100% { transform: translateY(100vh) rotate(360deg); }
}

/* Покачивание из стороны в сторону (может использоваться в связке со снегом) */
@keyframes sway {
  0% { transform: translateX(0); }
  50% { transform: translateX(15px); }
  100% { transform: translateX(-15px); }
}

/* Медиа-запросы для мобильных устройств.
  Если ширина экрана меньше 640px (смартфоны), контейнер будет иметь отступы по краям (px-4).
*/
@media (max-width: 640px) {
  .container {
    @apply px-4;
  }
}

/* Специальные стили для Telegram Mini App.
  Учитывают динамическую высоту окна Telegram, чтобы избежать проблем со скроллом и клавиатурой.
*/
.telegram-viewport {
  height: var(--tg-viewport-height, 100vh);
  height: var(--tg-viewport-stable-height, 100vh);
}

/* Адаптация для мобильных устройств с "челками" (Notch) на iOS/Android.
  Использует "безопасные зоны" (safe-area), чтобы контент не перекрывался системными элементами.
*/
@supports (padding: max(0px)) {
  body {
    padding-left: max(0px, env(safe-area-inset-left));
    padding-right: max(0px, env(safe-area-inset-right));
  }
}