import type { ReactNode } from "react";

export const metadata = {
  title: "Basecamp — anonymous forum (LP-0016)",
  description: "Reference app for anonymous posting with threshold moderation and membership revocation",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily: "system-ui, -apple-system, sans-serif",
          margin: 0,
          background: "#0b0d10",
          color: "#e6e8eb",
        }}
      >
        {children}
      </body>
    </html>
  );
}
