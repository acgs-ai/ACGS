import type { Metadata } from "next";
import type { ReactNode } from "react";

import { AppNavigation } from "@/components/page-content";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Second Brain", template: "%s · Second Brain" },
  description:
    "A private, provenance-first workspace for sources, evidence, and deliberate memory.",
};

export const dynamic = "force-dynamic";

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">
          Skip to main content
        </a>
        <header className="app-header">
          <div className="brand-block">
            <p className="brand">Second Brain</p>
            <p className="privacy-note">Private workspace · evidence first</p>
          </div>
          <AppNavigation />
        </header>
        <main id="main-content" tabIndex={-1}>
          {children}
        </main>
        <footer className="app-footer">
          Generated answers and memories remain distinct from original source material.
        </footer>
      </body>
    </html>
  );
}
