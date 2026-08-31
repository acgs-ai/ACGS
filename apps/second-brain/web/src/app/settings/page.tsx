import type { Metadata } from "next";

import { OrganizationSettings } from "@/components/organization-settings";
import { ProductPage } from "@/components/page-content";
import { StatusPanel } from "@/components/status-panel";
import { getServiceStatus } from "@/lib/server-api";

export const metadata: Metadata = { title: "Settings" };
export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  const status = await getServiceStatus();

  return (
    <ProductPage
      eyebrow="System"
      title="Settings"
      description="Inspect persistence, storage, and model-provider availability without exposing secrets."
    >
      <StatusPanel status={status} />
      <OrganizationSettings />
    </ProductPage>
  );
}
