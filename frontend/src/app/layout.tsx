import type { Metadata } from "next";
import { ThemeProvider, themeInitScript } from "@/components/ThemeProvider";
import "./globals.css";

export const metadata: Metadata = {
  title: "TrustTrace — Link & Scam Detective",
  description: "AI-powered web threat detection with blockchain-verified results. Analyze suspicious links and messages in seconds.",
  keywords: ["cybersecurity", "phishing detection", "scam detector", "blockchain verification", "threat intelligence"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="font-sans bg-zinc-50 dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 transition-colors duration-300 antialiased">
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
