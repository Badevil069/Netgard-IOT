import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "NetGuard IoT",
  description: "AI-driven rogue IoT device detection dashboard",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
