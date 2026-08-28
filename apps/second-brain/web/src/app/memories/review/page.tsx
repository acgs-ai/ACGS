import type { Metadata } from "next";

import { MemoryReviewView } from "@/components/memory-review-view";
import { ProductPage } from "@/components/page-content";

export const metadata: Metadata = { title: "Memory review" };

export default function MemoryReviewPage() {
  return (
    <ProductPage
      eyebrow="Proposed memory"
      title="Memory review"
      description="Approve, reject, or edit a proposal deliberately. A proposal is never active before approval."
    >
      <MemoryReviewView />
    </ProductPage>
  );
}
