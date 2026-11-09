import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Link & Scam Detective | Digital Trust Intelligence",
  description: "AI-Powered Web Threat Detection, TLS Inspection & Blockchain Verification",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased selection:bg-indigo-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
