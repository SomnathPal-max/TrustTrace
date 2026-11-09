import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TrustTrace | Web Threat Intelligence & Cryptographic Verification",
  description: "Enterprise CyberSOC Platform for Link & Scam Detection with EVM Blockchain Proofs",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var stored = localStorage.getItem('trusttrace-theme');
                  var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                  if (stored === 'light' || (!stored && !prefersDark)) {
                    document.documentElement.classList.remove('dark');
                  } else {
                    document.documentElement.classList.add('dark');
                  }
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body className="antialiased selection:bg-cyan-500/30 selection:text-cyan-600 dark:selection:text-cyan-200">
        {children}
      </body>
    </html>
  );
}
