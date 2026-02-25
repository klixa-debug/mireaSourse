/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  // Возвращаем статический экспорт для сборки в папку out
  output: 'export',
  distDir: 'out',
  env: {
    API_BASE_URL: process.env.API_BASE_URL,
    TELEGRAM_BOT_NAME: process.env.TELEGRAM_BOT_NAME,
  },
  // Настройки для статического экспорта
  trailingSlash: true,
  skipTrailingSlashRedirect: true,
}

export default nextConfig
