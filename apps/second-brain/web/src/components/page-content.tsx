import Link from "next/link";
import type { ReactNode } from "react";

export const NAV_ITEMS = [
  { href: "/today", label: "Today" },
  { href: "/inbox", label: "Inbox" },
  { href: "/library", label: "Library" },
  { href: "/search", label: "Search" },
  { href: "/ask", label: "Ask" },
  { href: "/memories", label: "Memories" },
  { href: "/memories/review", label: "Memory review" },
  { href: "/settings", label: "Settings" },
] as const;

export function AppNavigation() {
  return (
    <nav aria-label="Primary" className="primary-nav">
      <ul>
        {NAV_ITEMS.map((item) => (
          <li key={item.href}>
            <Link href={item.href}>{item.label}</Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}

interface ProductPageProps {
  eyebrow: string;
  title: string;
  description: string;
  state?: { label: string; detail: string };
  children?: ReactNode;
}

export function ProductPage({ eyebrow, title, description, state, children }: ProductPageProps) {
  return (
    <div className="page-stack">
      <header className="page-heading">
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="lede">{description}</p>
      </header>
      {children}
      {state ? (
        <section className="state-panel" aria-labelledby="state-heading">
          <p className="status-label">Unavailable</p>
          <h2 id="state-heading">{state.label}</h2>
          <p>{state.detail}</p>
        </section>
      ) : null}
    </div>
  );
}
