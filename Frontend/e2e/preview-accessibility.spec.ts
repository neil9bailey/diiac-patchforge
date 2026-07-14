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
