import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { installMockPatchForgeApi } from "./mockPatchForgeApi";

async function expectNoWcagViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();

  const summary = results.violations.map(({ id, impact, nodes }) => ({
    id,
    impact,
    targets: nodes.map((node) => node.target)
  }));
  expect(summary, JSON.stringify(summary, null, 2)).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await installMockPatchForgeApi(page);
});

test("admin preview supports the governed catalogue and keyboard VendorLens journey", async ({ page }) => {
  await page.goto("/?preview=1");

  await expect(page.getByRole("heading", { name: "What needs attention today?" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh KEV" })).toBeEnabled();
  await expect(page.getByText("CVE-2026-E2E-001", { exact: true }).first()).toBeVisible();
  await expect(page.locator('[data-label="CVE"]').first()).toBeVisible();
  await expectNoWcagViolations(page);

  await page.getByRole("button", { name: "Vendor Catalogue" }).click();
  const networkVendorsTab = page.getByRole("tab", { name: "Network Vendors" });
  const productFamiliesTab = page.getByRole("tab", { name: "Product Families" });
  await expect(networkVendorsTab).toHaveAttribute("aria-selected", "true");
  await networkVendorsTab.focus();
  await networkVendorsTab.press("ArrowRight");
  await expect(productFamiliesTab).toBeFocused();
  await expect(productFamiliesTab).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tabpanel", { name: "Product Families" })).toBeVisible();
  await expectNoWcagViolations(page);
});

test("reader preview preserves role boundaries and an accessible mobile drawer", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/?preview=1&previewRole=PatchForge.Reader");

  await expect(page.getByRole("button", { name: "Refresh KEV" })).toBeDisabled();

  const menuToggle = page.getByRole("button", { name: "Toggle navigation" });
  await menuToggle.click();
  const closeNavigation = page.getByRole("button", { name: "Close navigation", exact: true });
  await expect(closeNavigation).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(menuToggle).toBeFocused();
  await expect(menuToggle).toHaveAttribute("aria-expanded", "false");

  await menuToggle.click();
  await page.getByRole("button", { name: "Admin" }).click();
  await expect(page.getByText("PatchForge.Admin role required")).toBeVisible();
  await expectNoWcagViolations(page);
});

test("admin guidance explains tenant readiness and routes to verified report selection", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/?preview=1");
  await expect(page.getByRole("heading", { name: "What needs attention today?" })).toBeVisible();
  await page.getByRole("button", { name: "Getting started & guidance" }).click();

  const guide = page.getByRole("region", { name: "Guide", exact: true });
  await expect(guide.getByRole("heading", { name: "From advisory to accountable decision" })).toBeVisible();
  await expect(guide.getByText("Tenant: diiac.io", { exact: true })).toBeVisible();
  const packStep = guide.getByRole("article", { name: "Prepare a verified decision pack", exact: true });
  await expect(packStep.getByText("Responsibility: Your role can generate signed packs.", { exact: true })).toBeVisible();
  await expect(guide.getByText("No verified decision pack available", { exact: true })).toBeVisible();
  await expect(guide.getByRole("button", { name: "Open system health" })).toBeVisible();
  await expect(guide.getByRole("heading", { name: "Understand the trust states" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expectNoWcagViolations(page);

  await guide.getByRole("button", { name: "Choose a stakeholder report" }).click();
  const reports = page.getByRole("region", { name: "Reports", exact: true });
  await expect(reports.getByRole("heading", { name: "Select a verified decision pack" })).toBeVisible();
  await expect(reports.getByRole("combobox", { name: "Verified decision pack" })).toBeDisabled();
  await expect(reports.getByText("No QA bound to selected pack", { exact: true })).toBeVisible();
  const packRecords = reports.getByRole("region", { name: "Decision pack records" });
  await packRecords.focus();
  await expect(packRecords).toBeFocused();
  await expectNoWcagViolations(page);
});

test("reader mobile guidance provides accessible role handoffs and report navigation", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/?preview=1&previewRole=PatchForge.Reader");
  await expect(page.getByRole("heading", { name: "What needs attention today?" })).toBeVisible();

  const menuToggle = page.getByRole("button", { name: "Toggle navigation" });
  await menuToggle.click();
  await page.getByRole("button", { name: "Getting started & guidance" }).click();
  await expect(menuToggle).toHaveAttribute("aria-expanded", "false");

  const guide = page.getByRole("region", { name: "Guide", exact: true });
  await expect(guide.getByRole("heading", { name: "From advisory to accountable decision" })).toBeVisible();
  const packStep = guide.getByRole("article", { name: "Prepare a verified decision pack", exact: true });
  await expect(packStep.getByText("Responsibility: A Security Lead, CAB Approver, or Admin must generate the pack.", { exact: true })).toBeVisible();
  await expect(guide.getByRole("button", { name: "Open system health" })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expectNoWcagViolations(page);

  await guide.getByRole("button", { name: "Choose a stakeholder report" }).click();
  const reports = page.getByRole("region", { name: "Reports", exact: true });
  await expect(reports.getByRole("heading", { name: "Select a verified decision pack" })).toBeVisible();
  await expect(reports.getByRole("button", { name: "Generate Signed Pack" })).toBeDisabled();
  await expect(reports.getByRole("combobox", { name: "Verified decision pack" })).toBeDisabled();
  const packRecords = reports.getByRole("region", { name: "Decision pack records" });
  await packRecords.focus();
  await expect(packRecords).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expectNoWcagViolations(page);
});
