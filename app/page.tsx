import Landing from '@/components/landing';
import {authOptions} from '@/lib/auth-config';
export default function Home() {return <Landing options={authOptions()}/>;}
