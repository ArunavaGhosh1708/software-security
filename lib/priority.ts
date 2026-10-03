export type Priority = 'P0' | 'P1' | 'P2' | 'P3' | 'P4';

export const PRIORITIES: Record<Priority,{label:string;severity:string}> = {
  P0:{label:'Immediate',severity:'critical'},
  P1:{label:'High',severity:'high'},
  P2:{label:'Medium',severity:'medium'},
  P3:{label:'Low',severity:'low'},
  P4:{label:'Informational',severity:'info'}
};

// Preserve the existing risk ordering while exposing clear triage tiers.
export function priorityFromScore(score:number):Priority {
  if(score>=75)return 'P0';
  if(score>=50)return 'P1';
  if(score>=25)return 'P2';
  if(score>=10)return 'P3';
  return 'P4';
}
