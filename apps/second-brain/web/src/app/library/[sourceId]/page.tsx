import type { Metadata } from "next";

import { ProductPage } from "@/components/page-content";
import { SourceDetailView } from "@/components/source-detail-view";

export const metadata: Metadata = { title: "Source detail" };

interface SourceDetailPageProps {
  params: Promise<{ sourceId: string }>;
  searchParams: Promise<{ chunk?: string; start?: string; end?: string }>;
}

export default async function SourceDetailPage({ params, searchParams }: SourceDetailPageProps) {
  const { sourceId } = await params;
  const { chunk, start, end } = await searchParams;
  const validId = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    sourceId,
  );
  const validChunk =
    chunk === undefined ||
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(chunk);
  const startOffset = start === undefined ? undefined : Number(start);
  const endOffset = end === undefined ? undefined : Number(end);
  const validOffsets =
    (startOffset === undefined && endOffset === undefined) ||
    (Number.isSafeInteger(startOffset) &&
      Number.isSafeInteger(endOffset) &&
      (startOffset as number) >= 0 &&
      (endOffset as number) > (startOffset as number));

  return (
    <ProductPage
      eyebrow="Source"
      title="Source detail"
      description="Original metadata, extracted content, processing history, and citation context remain distinct."
    >
      {validId && validChunk && validOffsets ? (
        <SourceDetailView
          {...(chunk ? { selectedChunkId: chunk } : {})}
          {...(startOffset !== undefined && endOffset !== undefined
            ? { selectedStart: startOffset, selectedEnd: endOffset }
            : {})}
          sourceId={sourceId}
        />
      ) : (
        <section className="state-panel">
          <p className="status-label">Citation unavailable</p>
          <h2>Invalid source reference</h2>
          <p>The source or chunk identifier is invalid and was not requested.</p>
        </section>
      )}
    </ProductPage>
  );
}
