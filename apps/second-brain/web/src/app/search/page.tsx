import type { Metadata } from "next";

import { ProductPage } from "@/components/page-content";
import { SearchView } from "@/components/search-view";

export const metadata: Metadata = { title: "Search" };

export default function SearchPage() {
  return (
    <ProductPage
      eyebrow="Retrieval"
      title="Search"
      description="Find source passages through lexical and semantic retrieval with visible ranks and stable IDs."
    >
      <SearchView />
    </ProductPage>
  );
}
