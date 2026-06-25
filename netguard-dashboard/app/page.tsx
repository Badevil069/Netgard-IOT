"use client";

import dynamic from "next/dynamic";

const DashboardPage = dynamic(
  () => import("./Dashboard").then((mod) => mod.default),
  { ssr: false }
);

export default function Page() {
  return <DashboardPage />;
}
