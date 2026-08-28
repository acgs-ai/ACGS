import type { Metadata } from "next";

import { LibraryView } from "@/components/library-view";
import { ProductPage } from "@/components/page-content";

export const metadata: Metadata = { title: "Library" };

export default function LibraryPage() {
  return (
    <ProductPage
      eyebrow="Sources"
      title="Library"
      description="Inspect source metadata, extracted content, chunk boundaries, ingestion history, and deletion state."
    >
      <LibraryView />
    </ProductPage>
  );
}
