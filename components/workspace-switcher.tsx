'use client';
import {useEffect,useState} from 'react';
import {api} from '@/lib/client';
export default function WorkspaceSwitcher({current}:{current:string}) {
  const [items,setItems]=useState<{id:string;name:string;role:string}[]>([]);
  useEffect(()=>{api('organizations').then(setItems).catch(()=>{});},[current]);
  return <label className="workspace"><span className="workspace-avatar">S</span><select aria-label="Workspace" value={current} onChange={e=>{localStorage.setItem('sentinel.organization',e.target.value);window.location.reload();}}>{items.length?items.map(o=><option value={o.id} key={o.id}>{o.name} · {o.role}</option>):<option value={current}>My workspace</option>}</select></label>;
}
