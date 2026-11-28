import {workerData,parentPort} from 'node:worker_threads';
import {EntitlementStore} from './state.mjs';
import {Invalid} from './validator.mjs';
const {path,config,now,action,id,barrier}=workerData;
const gate=new Int32Array(barrier);
Atomics.add(gate,0,1);Atomics.notify(gate,0);
while(Atomics.load(gate,0)<2){
  if(Atomics.wait(gate,0,1,5000)==='timed-out')throw new Error('worker barrier timeout');
}
try{parentPort.postMessage(new EntitlementStore(path,config,()=>now).execute(action,id,id));}
catch(e){if(e instanceof Invalid)parentPort.postMessage('denied');else throw e;}
