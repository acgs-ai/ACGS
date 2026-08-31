import type { Metadata } from "next";

import { AskView } from "@/components/ask-view";
import { ProductPage } from "@/components/page-content";

export const metadata: Metadata = { title: "Ask" };

export default function AskPage() {
  return (
    <ProductPage
      eyebrow="Evidence"
      title="Ask"
      description="Ask a question and inspect every validated citation used by a source-supported answer."
    >
      <AskView />
    </ProductPage>
  );
}
