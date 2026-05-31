import { CaptureProvider } from "@/hooks/usePacketCapture";
import { Layout } from "@/components/Layout";

export default function App() {
  return (
    <CaptureProvider>
      <Layout />
    </CaptureProvider>
  );
}
