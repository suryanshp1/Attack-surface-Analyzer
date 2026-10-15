import type { Metadata } from "next";
import "./globals.css";
import { AppearanceProvider } from "@/components/appearance";
import { appearanceBootstrap } from "@/lib/appearance-bootstrap";
export const metadata: Metadata = {
  title: "Surfacer — Your surface, in sight.",
  description:
    "Discover your external assets, track changes, and prioritize exposures in one security workspace.",
};
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: appearanceBootstrap }} />
      </head>
      <body>
        <AppearanceProvider>{children}</AppearanceProvider>
      </body>
    </html>
  );
}
