// ===== Helpers =====
const esc = (s) => String(s)
  .replace(/&/g,'&amp;')
  .replace(/</g,'&lt;')
  .replace(/>/g,'&gt;')
  .replace(/\"/g,'&quot;')
  .replace(/'/g,'&#39;');

// ===== Core System =====
class ProductionChainSystem {
  constructor(){
    this.processors=new Map();
    this.inputToProcessors=new Map();
    this.outputToProcessors=new Map();
    this.updateStats();
  }
  async addProcessor(name,inputs,outputs,processingTime='',description=''){
    if(!name||!name.trim()) throw new Error('Processor name is required');
    if(this.processors.has(name.trim())) throw new Error(`Processor "${name.trim()}" already exists in the approved directory`);
    const p={name:name.trim(),inputs:inputs.map(i=>i.trim()).filter(Boolean),outputs:outputs.map(o=>o.trim()).filter(Boolean),processingTime:processingTime.trim(),description:description.trim()};
    if(p.inputs.length===0) throw new Error('At least one input is required');
    if(p.outputs.length===0) throw new Error('At least one output is required');
    return await AppDataStore.submitProcessor(p.name, p.inputs, p.outputs, p.processingTime, p.description);
  }
  findProcessorsByInputs(availableInputs,allowPartial=true){
    const res={exactMatches:[],partialMatches:[],possibleOutputs:new Set(),secondaryProcessors:[]};
    this.processors.forEach((p,name)=>{
      const req=p.inputs; let cnt=0;
      req.forEach(r=>{ availableInputs.forEach(av=>{ if(allowPartial){ if(r.toLowerCase().includes(av.toLowerCase())||av.toLowerCase().includes(r.toLowerCase())) cnt++; } else if(r===av) cnt++; }); });
      if(cnt===req.length&&req.length>0){ res.exactMatches.push({processor:name,data:p}); p.outputs.forEach(o=>res.possibleOutputs.add(o)); }
      else if(cnt>0){ const missing=req.filter(inp=>!availableInputs.some(av=>allowPartial?(inp.toLowerCase().includes(av.toLowerCase())||av.toLowerCase().includes(inp.toLowerCase())):(inp===av))); res.partialMatches.push({processor:name,data:p,matchCount:cnt,missingInputs:missing}); }
    });
    res.possibleOutputs.forEach(o=>{ if(this.inputToProcessors.has(o)){ this.inputToProcessors.get(o).forEach(n=>{ if(!res.exactMatches.some(m=>m.processor===n)){ res.secondaryProcessors.push({processor:n,data:this.processors.get(n),triggerInput:o}); } }); } });
    return res;
  }
  findProductionChain(start,maxDepth=5){
    const chains=[]; const visited=new Set();
    const explore=(currentInputs,chain,depth)=>{
      if(depth>=maxDepth) return; const key=chain.map(c=>c.processor).join('-')+'-'+currentInputs.join(','); if(visited.has(key)) return; visited.add(key);
      this.processors.forEach((p,name)=>{
        const can=p.inputs.some(req=>currentInputs.some(av=>req.toLowerCase().includes(av.toLowerCase())||av.toLowerCase().includes(req.toLowerCase())));
        if(can){ const newChain=[...chain,{step:depth+1,inputs:p.inputs,processor:name,outputs:p.outputs,processingTime:p.processingTime}]; chains.push(newChain); if(depth<maxDepth-1) explore(p.outputs,newChain,depth+1); }
      });
    };
    explore([start],[],0); return chains.sort((a,b)=>b.length-a.length);
  }
  findInputFlow(input,maxDepth=4){
    const flow={input,levels:[]}; let cur=[input]; const seen=new Set();
    for(let d=0; d<maxDepth && cur.length>0; d++){
      const next=new Set(); const level={depth:d,processors:[],outputs:new Set()};
      cur.forEach(inp=>{ if(seen.has(inp)) return; seen.add(inp);
        this.processors.forEach((p,name)=>{ const can=p.inputs.some(req=>req.toLowerCase().includes(inp.toLowerCase())||inp.toLowerCase().includes(req.toLowerCase())); if(can && !level.processors.some(x=>x.name===name)){ level.processors.push({name,data:p,triggerInput:inp}); p.outputs.forEach(o=>{ level.outputs.add(o); next.add(o); }); } });
      });
      if(level.processors.length===0) break; flow.levels.push(level); cur=Array.from(next);
    }
    return flow;
  }
  updateStats(){
    const pc = document.getElementById('processors-count'); if(pc) pc.textContent=this.processors.size;
    let chains=0; this.processors.forEach(p=>chains+=p.outputs.length);
    const cc=document.getElementById('chains-count'); if(cc) cc.textContent=chains;
    const allIn=new Set(), allOut=new Set(); this.processors.forEach(p=>{ p.inputs.forEach(i=>allIn.add(i)); p.outputs.forEach(o=>allOut.add(o)); });
    const ic=document.getElementById('inputs-count'); if(ic) ic.textContent=allIn.size; const oc=document.getElementById('outputs-count'); if(oc) oc.textContent=allOut.size; this.updateDropdowns();
  }
  updateDropdowns(){
    const cs=document.getElementById('chain-start'); const fs=document.getElementById('flow-input');
    if(!cs||!fs) return;
    cs.innerHTML='<option value="">Choose a starting input...</option>'; fs.innerHTML='<option value="">Choose an input...</option>';
    const allInputs=new Set(); this.processors.forEach(p=>p.inputs.forEach(i=>allInputs.add(i)));
    Array.from(allInputs).sort().forEach(i=>{ const o1=document.createElement('option'); o1.value=i; o1.textContent=i; cs.appendChild(o1); const o2=document.createElement('option'); o2.value=i; o2.textContent=i; fs.appendChild(o2); });
  }
  getAllProcessors(){ return Array.from(this.processors.entries()).map(([name,data])=>({name,...data})); }
  searchProcessors(q){ const out=[]; const s=q.toLowerCase(); this.processors.forEach((p,name)=>{ let score=0; const hl={name,inputs:[...p.inputs],outputs:[...p.outputs],description:p.description}; if(name.toLowerCase().includes(s)){ score+=10; hl.name=esc(name).replace(new RegExp(`(${q})`,'gi'),'<span style="background:#ffeb3b">$1</span>'); } p.inputs.forEach((i,idx)=>{ if(i.toLowerCase().includes(s)){ score+=5; hl.inputs[idx]=esc(i).replace(new RegExp(`(${q})`,'gi'),'<span style="background:#ffeb3b">$1</span>'); } }); p.outputs.forEach((o,idx)=>{ if(o.toLowerCase().includes(s)){ score+=5; hl.outputs[idx]=esc(o).replace(new RegExp(`(${q})`,'gi'),'<span style="background:#ffeb3b">$1</span>'); } }); if(p.description && p.description.toLowerCase().includes(s)){ score+=3; hl.description=esc(p.description).replace(new RegExp(`(${q})`,'gi'),'<span style="background:#ffeb3b">$1</span>'); } if(score>0) out.push({name,data:p,relevanceScore:score,highlights:hl}); }); return out.sort((a,b)=>b.relevanceScore-a.relevanceScore); }
}

const system=new ProductionChainSystem();
let selectedInputs=[];

// ===== UI Helpers =====
function showMessage(msg,type){ document.querySelectorAll('.success-message,.error-message').forEach(m=>m.remove()); const d=document.createElement('div'); d.className=(type==='success')?'success-message':'error-message'; d.textContent=msg; const area=document.querySelector('.content-area'); area.insertBefore(d,area.firstChild); setTimeout(()=>d.remove(),4500);}
function showTab(tab,btn){ document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active')); document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active')); document.getElementById(`${tab}-tab`).classList.add('active'); if(btn) btn.classList.add('active'); if(tab==='processors') displayAllProcessors(); }
function refreshActiveTab(){
  if(document.getElementById('processors-tab').classList.contains('active')){ displayAllProcessors(); return; }
  if(document.getElementById('chains-tab').classList.contains('active')){ document.getElementById('chain-visualization').innerHTML=''; return; }
  if(document.getElementById('flow-tab').classList.contains('active')){ document.getElementById('flow-visualization').innerHTML=''; }
}

// ===== Add Processor (UI) =====
async function addProcessor(){
  const name = document.getElementById('processor-name').value.trim();
  const inputs = document.getElementById('processor-inputs').value.split(',').map(s=>s.trim()).filter(Boolean);
  const outputs = document.getElementById('processor-outputs').value.split(',').map(s=>s.trim()).filter(Boolean);
  const processingTime = document.getElementById('processing-time').value.trim();
  const description = document.getElementById('processor-description').value.trim();
  if(!name){ showMessage('Processor name is required.','error'); return; }
  if(inputs.length===0){ showMessage('At least one input is required.','error'); return; }
  if(outputs.length===0){ showMessage('At least one output is required.','error'); return; }
  try{
    const result = await system.addProcessor(name, inputs, outputs, processingTime, description);
    document.getElementById('processor-name').value = '';
    document.getElementById('processor-inputs').value = '';
    document.getElementById('processor-outputs').value = '';
    document.getElementById('processing-time').value = '';
    document.getElementById('processor-description').value = '';
    showMessage(`Processor "${result.name}" submitted for admin approval.`, 'success');
  }catch(e){ showMessage('Error adding processor: ' + e.message, 'error'); }
}

// ===== Discovery =====
function addInputChip(){ const v=document.getElementById('input-search').value.trim(); if(v && !selectedInputs.includes(v)){ selectedInputs.push(v); updateInputChips(); document.getElementById('input-search').value=''; } }
function removeInputChip(x){ selectedInputs=selectedInputs.filter(i=>i!==x); updateInputChips(); }
function updateInputChips(){ const c=document.getElementById('input-chips'); c.innerHTML=''; selectedInputs.forEach(inp=>{ const chip=document.createElement('div'); chip.className='chip'; chip.innerHTML=`${esc(inp)} <button class="chip-remove" onclick="removeInputChip('${inp.replace(/'/g,"\\'")}')">x</button>`; c.appendChild(chip); }); }
function clearInputs(){ selectedInputs=[]; updateInputChips(); document.getElementById('discovery-results').innerHTML=''; }
function discoverPossibilities(){ if(selectedInputs.length===0){ showMessage('Please add some inputs first.','error'); return; } const r=system.findProcessorsByInputs(selectedInputs,true); displayDiscoveryResults(r); }
function quickDiscover(){ const arr=document.getElementById('quick-inputs').value.split(',').map(s=>s.trim()).filter(Boolean); if(arr.length===0){ showMessage('Please enter some inputs.','error'); return; } selectedInputs=arr; updateInputChips(); discoverPossibilities(); showTab('discovery', document.querySelector('.tab:nth-child(1)')); }
function findOptimalChain(){ if(selectedInputs.length===0){ showMessage('Please add some inputs first.','error'); return; } const r=system.findProcessorsByInputs(selectedInputs,true); displayOptimalChain(r); }

function displayDiscoveryResults(results){ const el=document.getElementById('discovery-results'); let html='<div class="results-container">'; if(results.exactMatches.length>0){ html+='<div class="result-section"><h4>Ready-to-Process</h4><div class="result-grid">'; results.exactMatches.forEach(m=>{ html+=`<div class="result-card"><strong>${esc(m.processor)}</strong><div><b>Outputs:</b> ${m.data.outputs.map(esc).join(', ')}<br/><b>Time:</b> ${esc(m.data.processingTime||'N/A')}<br/><small>${esc(m.data.description||'')}</small></div></div>`; }); html+='</div></div>'; } if(results.partialMatches.length>0){ html+='<div class="result-section"><h4>Partial Matches</h4><div class="result-grid">'; results.partialMatches.forEach(m=>{ html+=`<div class="result-card"><strong>${esc(m.processor)}</strong><div><b>Missing:</b> ${m.missingInputs.map(esc).join(', ')}<br/><b>Would produce:</b> ${m.data.outputs.map(esc).join(', ')}<br/><small>${esc(m.data.description||'')}</small></div></div>`; }); html+='</div></div>'; } if(results.secondaryProcessors.length>0){ html+='<div class="result-section"><h4>Secondary Opportunities</h4><div class="result-grid">'; results.secondaryProcessors.forEach(m=>{ html+=`<div class="result-card"><strong>${esc(m.processor)}</strong><div><b>Uses:</b> ${esc(m.triggerInput)}<br/><b>Produces:</b> ${m.data.outputs.map(esc).join(', ')}<br/><b>Also needs:</b> ${m.data.inputs.filter(i=>i!==m.triggerInput).map(esc).join(', ')||'Nothing else!'}<br/><small>${esc(m.data.description||'')}</small></div></div>`; }); html+='</div></div>'; } if(results.exactMatches.length===0 && results.partialMatches.length===0 && results.secondaryProcessors.length===0){ html+='<div class="result-section"><h4>No Matches Found</h4><p>Try adding different inputs or restore the base dataset.</p></div>'; } html+='</div>'; el.innerHTML=html; }

function displayOptimalChain(results){ const el=document.getElementById('discovery-results'); let html='<div class="results-container"><h4>Optimal Production Chain</h4>'; if(results.exactMatches.length>0){ const scored=results.exactMatches.map(m=>{ let s=0; m.data.outputs.forEach(o=>{ if(system.inputToProcessors.has(o)){ s+=system.inputToProcessors.get(o).size; } }); return {...m,score:s}; }).sort((a,b)=>b.score-a.score); const best=scored[0]; html+='<div class="chain-visualization">'; html+=`<div class="chain-step"><div class="chain-item"><b>Available Inputs</b><div>${selectedInputs.map(esc).join(', ')}</div></div><div class="chain-arrow">-></div><div class="chain-item"><b>${esc(best.processor)}</b><div>${esc(best.data.processingTime||'Varies')}</div></div><div class="chain-arrow">-></div><div class="chain-item"><b>Outputs</b><div>${best.data.outputs.map(esc).join(', ')}</div></div></div>`; html+='</div>'; } else { html+='<p>No optimal chain found for current inputs.</p>'; } html+='</div>'; el.innerHTML=html; }

// ===== Processors table =====
function displayAllProcessors(){ const c=document.getElementById('processors-list'); const list=system.getAllProcessors(); if(list.length===0){ c.innerHTML='<p>No approved processors found. If the Supabase table has rows, wait a moment for the page to finish loading and try the tab again.</p>'; return; } let h=`<table class="data-table"><thead><tr><th>Processor</th><th>Inputs</th><th>Outputs</th><th>Time</th><th>Actions</th></tr></thead><tbody>`; list.forEach(p=>{ h+=`<tr><td><strong>${esc(p.name)}</strong><br/><small>${esc(p.description||'-')}</small></td><td>${p.inputs.map(esc).join(', ')}</td><td>${p.outputs.map(esc).join(', ')}</td><td>${esc(p.processingTime||'N/A')}</td><td><button class="btn btn-small btn-warning" onclick="useAsTemplate('${p.name.replace(/'/g,"\\'")}')">Template</button></td></tr>`; }); c.innerHTML=h+'</tbody></table>'; }
function filterProcessors(){ const f=document.getElementById('processor-filter').value.trim(); if(!f){ displayAllProcessors(); return; } const r=system.searchProcessors(f); const c=document.getElementById('processors-list'); if(r.length===0){ c.innerHTML='<p>No approved processors found.</p>'; return; } let h=`<table class="data-table"><thead><tr><th>Processor</th><th>Inputs</th><th>Outputs</th><th>Time</th><th>Actions</th></tr></thead><tbody>`; r.forEach(x=>{ h+=`<tr><td><strong>${x.highlights.name}</strong><br/><small>${x.highlights.description||'-'}</small></td><td>${x.highlights.inputs.join(', ')}</td><td>${x.highlights.outputs.join(', ')}</td><td>${esc(x.data.processingTime||'N/A')}</td><td><button class="btn btn-small btn-warning" onclick="useAsTemplate('${x.name.replace(/'/g,"\\'")}')">Template</button></td></tr>`; }); c.innerHTML=h+'</tbody></table>'; }
function clearFilter(){ document.getElementById('processor-filter').value=''; displayAllProcessors(); }
function useAsTemplate(name){ const p=system.processors.get(name); if(p){ document.getElementById('processor-name').value=p.name+' (Copy)'; document.getElementById('processor-inputs').value=p.inputs.join(', '); document.getElementById('processor-outputs').value=p.outputs.join(', '); document.getElementById('processing-time').value=p.processingTime; document.getElementById('processor-description').value=p.description; showTab('discovery', document.querySelector('.tab:nth-child(1)')); showMessage('Template loaded. Edit then click Add Processor.','success'); } }

// ===== Chains =====
function visualizeChain(){ const start=document.getElementById('chain-start').value; if(!start){ showMessage('Please select a starting input.','error'); return; } const chains=system.findProductionChain(start,3); displayChainVisualization(chains,start); }
function visualizeAllChains(){ const allInputs=new Set(); system.processors.forEach(p=>p.inputs.forEach(i=>allInputs.add(i))); const c=document.getElementById('chain-visualization'); let h='<div class="results-container"><h4>All Production Chains Overview</h4>'; Array.from(allInputs).slice(0,10).forEach(inp=>{ const chains=system.findProductionChain(inp,2); if(chains.length>0){ const procs=[...new Set(chains.map(ch=>ch[0]?.processor).filter(Boolean))]; const outs=new Set(); chains.forEach(ch=>ch.forEach(st=>st.outputs.forEach(o=>outs.add(o)))); h+=`<div class="chain-visualization"><div class="chain-step"><div class="chain-item"><b>${esc(inp)}</b><div>Raw</div></div><div class="chain-arrow">-></div><div class="chain-item"><b>Processors</b><div>${procs.slice(0,3).map(esc).join(', ')}${procs.length>3?'...':''}</div></div><div class="chain-arrow">-></div><div class="chain-item"><b>Final</b><div>${Array.from(outs).slice(0,5).map(esc).join(', ')}${outs.size>5?'...':''}</div></div></div></div>`; } }); c.innerHTML=h+'</div>'; }
function displayChainVisualization(chains,startInput){ const c=document.getElementById('chain-visualization'); if(!chains||chains.length===0){ c.innerHTML=`<div class='results-container'><h4>No Production Chains Found</h4><p>No chains found for "${esc(startInput)}".</p></div>`; return; } let h='<div class="results-container">'; h+=`<h4>Production Chains from "${esc(startInput)}"</h4>`; chains.slice(0,5).forEach((chain,idx)=>{ h+='<div class="chain-visualization">'; h+=`<h5>Chain ${idx+1} (${chain.length} steps)</h5><div class="chain-step"><div class="chain-item"><b>Starting</b><div>${esc(startInput)}</div></div>`; chain.forEach((step,i)=>{ h+=`<div class='chain-arrow'>-></div><div class='chain-item'><b>Step ${i+1}: ${esc(step.processor)}</b><div>Time: ${esc(step.processingTime||'Varies')}</div><small>Outputs: ${step.outputs.map(esc).join(', ')}</small></div>`; }); h+='</div></div>'; }); h+='</div>'; c.innerHTML=h; }

// ===== Flow =====
function visualizeInputFlow(){
  try{
    const inp=document.getElementById('flow-input').value;
    if(!inp){ showMessage('Select an input first.','error'); return; }
    const flow=system.findInputFlow(inp,4);
    const c=document.getElementById('flow-visualization');
    let h='<div class="results-container">';
    const inputLabel=esc(flow.input);
    h+=`<h4>Processing Flow for "${inputLabel}"</h4><div class="flow-diagram">`;
    h+=`<div class='flow-level'><div class='flow-node'>${inputLabel}</div></div>`;
    if(!flow.levels || flow.levels.length===0){
      h+=`<div class='flow-level'><em>No processors found that use ${inputLabel}. Try another input or restore base data.</em></div>`;
      h+='</div></div>';
      c.innerHTML=h; return;
    }
    flow.levels.forEach((lvl,idx)=>{
      h+=`<div class='flow-connector'>v</div><div class='flow-level'><b>Level ${idx+1} Processing</b><br/>`;
      lvl.processors.forEach(p=>{
        const title=esc(p.data?.description||'');
        const name=esc(p.name);
        h+=`<span class='flow-node' title="${title}">${name}</span>`;
      });
      h+='</div>';
      if(lvl.outputs && lvl.outputs.size>0){
        h+=`<div class='flow-connector'>v</div><div class='flow-level'><b>Level ${idx+1} Outputs</b><br/>`;
        Array.from(lvl.outputs).forEach(o=>{ h+=`<span class='flow-node'>${esc(o)}</span>`; });
        h+='</div>';
      }
    });
    h+='</div></div>';
    c.innerHTML=h;
  }catch(e){ console.error(e); showMessage('Could not render Input Flow (check console).','error'); }
}

function visualizeCompleteFlow(){
  const c = document.getElementById('flow-visualization');
  let h = '<div class="results-container"><h4>Complete Processing Network</h4>';
  const allIn = new Set(), allOut = new Set();
  system.processors.forEach(p => { p.inputs.forEach(i => allIn.add(i)); p.outputs.forEach(o => allOut.add(o)); });
  const primary = Array.from(allIn).filter(i => !allOut.has(i));
  const interm  = Array.from(allIn).filter(i =>  allOut.has(i));
  h += '<div class="flow-diagram">';
  if (primary.length > 0) {
    h += '<div class="flow-level"><b>Primary Raw Materials</b><br/>';
    primary.slice(0,15).forEach(i => { h += `<span class='flow-node'>${esc(i)}</span>`; });
    h += '</div><div class="flow-connector">v</div>';
  }
  h += '<div class="flow-level"><b>Processing Units</b><br/>';
  Array.from(system.processors.keys()).slice(0,20).forEach(n => { h += `<span class='flow-node'>${esc(n)}</span>`; });
  h += '</div><div class="flow-connector">v</div>';
  if (interm.length > 0) {
    h += '<div class="flow-level"><b>Intermediate Products</b><br/>';
    interm.slice(0,15).forEach(i => { h += `<span class='flow-node'>${esc(i)}</span>`; });
    h += '</div><div class="flow-connector">v</div>';
  }
  const finals = Array.from(allOut).filter(o => !allIn.has(o));
  if (finals.length > 0) {
    h += '<div class="flow-level"><b>Final Products</b><br/>';
    finals.slice(0,20).forEach(o => { h += `<span class='flow-node'>${esc(o)}</span>`; });
    h += '</div>';
  }
  h += '</div></div>';
  c.innerHTML = h;
}

// ===== Event listeners =====
document.getElementById('input-search').addEventListener('keypress',e=>{ if(e.key==='Enter') addInputChip(); });
document.getElementById('processor-filter').addEventListener('keypress',e=>{ if(e.key==='Enter') filterProcessors(); });
document.addEventListener('DOMContentLoaded', async ()=>{
  updateInputChips();
  try{
    const count = await AppDataStore.loadProcessors(system);
    if(count===0){
      showMessage('Supabase table is empty.','error');
    }
  }catch(e){
    showMessage(e.message,'error');
  }
  refreshActiveTab();
});
