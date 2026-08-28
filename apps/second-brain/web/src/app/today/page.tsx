import type { Metadata } from "next";

import { ProductPage } from "@/components/page-content";
import { TodayView } from "@/components/today-view";

export const metadata: Metadata = { title: "Today" };

export default function TodayPage() {
  return (
    <ProductPage
      eyebrow="Overview"
      title="Today"
      description="Recent captures, processing failures, approved memories, and deterministic resurfacing."
    >
      <TodayView />
    </ProductPage>
  );
}
