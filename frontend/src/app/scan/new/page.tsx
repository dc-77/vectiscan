// VEC-312: Scan-Wizard /scan/new — wird in VEC-312 ausgebaut.
// Für jetzt: leitet auf /scan (bestehender Scan-Form) um, damit der
// AppShell-NavItem "Neuer Scan" → /scan/new schon sauber verlinkt ist.
import { redirect } from 'next/navigation';
export default function ScanNewPage() {
  redirect('/scan');
}
