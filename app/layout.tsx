import type {Metadata} from 'next';
import {connection} from 'next/server';
import './globals.css';
export const metadata:Metadata={title:'Sentinel · Security guardrails',description:'Security assessments, code quality, guardrails, and runtime signals in one workspace.'};
export default async function Layout({children}:{children:React.ReactNode}) {
  await connection();
  return <html lang="en">
    {/* Browser extensions such as Grammarly inject body attributes before hydration. */}
    <body suppressHydrationWarning>{children}</body>
  </html>;
}
