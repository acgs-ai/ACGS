import type { Metadata } from "next";

import { MemoryLibraryView } from "@/components/memory-library-view";
import { ProductPage } from "@/components/page-content";

export const metadata: Metadata = { title: "Approved memories" };

export default function MemoriesPage() {
  return (
    <ProductPage
      eyebrow="Durable memory"
      title="Approved memories"
      description="Review active memory, evidence lineage, revisions, supersession, archive, and purge state."
    >
      <MemoryLibraryView />
    </ProductPage>
  );
}
