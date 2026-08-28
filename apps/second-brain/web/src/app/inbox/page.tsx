import type { Metadata } from "next";

import { CapturePanel } from "@/components/capture-panel";
import { ProductPage } from "@/components/page-content";

export const metadata: Metadata = { title: "Inbox" };

export default function InboxPage() {
  return (
    <ProductPage
      eyebrow="Capture"
      title="Inbox"
      description="Preserve notes, Markdown, TXT, PDF, DOCX, and safe public URLs with source provenance."
    >
      <CapturePanel />
    </ProductPage>
  );
}
