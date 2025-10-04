import { Geist, Geist_Mono } from "next/font/google";
import { Toaster } from "sonner";
import { RealtimeProvider } from "@/components/providers/RealtimeProvider";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import ErrorBoundary from "@/components/common/ErrorBoundary";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata = {
  title: "Bug Hunt Framework",
  description: "Professional Bug Bounty Automation Platform",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased pl-4`}
      >
        <ErrorBoundary>
          <ThemeProvider>
            <AuthProvider>
              <RealtimeProvider>
                {children}
              </RealtimeProvider>
            </AuthProvider>
          </ThemeProvider>
        </ErrorBoundary>
        <Toaster
          position="top-right"
          theme="dark"
          richColors
          closeButton
          duration={4000}
          toastOptions={{
            className: 'border border-gray-700 bg-gray-800/90 backdrop-blur-sm',
          }}
        />
      </body>
    </html>
  );
}
