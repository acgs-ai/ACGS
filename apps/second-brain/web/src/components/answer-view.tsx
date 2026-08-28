import Link from "next/link";

import { safeParseAnswerRecord } from "@/lib/answer-parser";
import { getRenderableAnswer } from "@/lib/contracts";

export function AnswerView({ answer }: { answer: unknown }) {
  const parsed = safeParseAnswerRecord(answer);
  if (!parsed) {
    return (
      <section className="answer-state" aria-labelledby="answer-state-heading">
        <p className="status-label">Citation unavailable</p>
        <h2 id="answer-state-heading">Answer contract rejected</h2>
        <p>The answer could not be validated against accessible retrieved evidence.</p>
      </section>
    );
  }
  const display = getRenderableAnswer(parsed);

  if (display.kind === "validation_failed") {
    return (
      <section className="answer-state" aria-labelledby="answer-state-heading">
        <p className="status-label">Citation unavailable</p>
        <h2 id="answer-state-heading">Citation validation failed</h2>
        <p>{display.message}</p>
        {display.fallback.length > 0 ? (
          <div className="evidence-block">
            <h3>Validated extractive fallback</h3>
            {display.fallback.map((item) => (
              <blockquote key={item.citation.citation_id}>
                <p>{item.text}</p>
                <CitationLink citation={item.citation} />
              </blockquote>
            ))}
          </div>
        ) : null}
      </section>
    );
  }

  if (display.kind === "insufficient_evidence") {
    return (
      <section className="answer-state" aria-labelledby="answer-state-heading">
        <p className="status-label">Insufficient evidence</p>
        <h2 id="answer-state-heading">No source-supported answer</h2>
        <p>{display.message}</p>
        {display.commentary ? <SystemCommentary text={display.commentary} /> : null}
      </section>
    );
  }

  if (display.kind === "provider_unavailable") {
    return (
      <section className="answer-state" aria-labelledby="answer-state-heading">
        <p className="status-label">Provider unavailable</p>
        <h2 id="answer-state-heading">Answer generation unavailable</h2>
        <p>{display.message}</p>
        {display.commentary ? <SystemCommentary text={display.commentary} /> : null}
      </section>
    );
  }

  return (
    <article className="answer-state" aria-labelledby="answer-state-heading">
      <p className="status-label">Grounded answer</p>
      <h2 id="answer-state-heading">Source-supported response</h2>
      <ol className="answer-statements">
        {display.statements.map((statement) => (
          <li key={statement.statement_id}>
            <p>{statement.text}</p>
            <p className="citation-list">
              {statement.citations.map((citation) => (
                <CitationLink key={citation.citation_id} citation={citation} />
              ))}
            </p>
          </li>
        ))}
      </ol>
      {display.commentary ? <SystemCommentary text={display.commentary} /> : null}
    </article>
  );
}

function CitationLink({
  citation,
}: {
  citation: { source_id: string; chunk_id: string; char_start: number; char_end: number };
}) {
  return (
    <Link
      href={`/library/${encodeURIComponent(citation.source_id)}?chunk=${encodeURIComponent(citation.chunk_id)}&start=${citation.char_start}&end=${citation.char_end}`}
    >
      Inspect evidence
    </Link>
  );
}

function SystemCommentary({ text }: { text: string }) {
  return (
    <aside className="system-commentary" aria-label="System commentary">
      <h3>System commentary</h3>
      <p>{text}</p>
    </aside>
  );
}
