const AppDataStore = (() => {
  const TABLE = () => (window.APP_CONFIG && window.APP_CONFIG.SUPABASE_TABLE) || 'processors';
  let client = null;

  function getClient(){
    if(client) return client;
    const config = window.APP_CONFIG || {};
    if(!config.SUPABASE_URL || !config.SUPABASE_ANON_KEY) throw new Error('Missing Supabase config. Check generated config.js.');
    if(!window.supabase || typeof window.supabase.createClient !== 'function') throw new Error('Supabase client library failed to load.');
    client = window.supabase.createClient(config.SUPABASE_URL, config.SUPABASE_ANON_KEY);
    return client;
  }

  function normalizeProcessor(name, inputs, outputs, processingTime = '', description = ''){
    if(!name || !name.trim()) throw new Error('Processor name is required');
    const processor = {
      name: name.trim(),
      inputs: (inputs || []).map((item) => String(item).trim()).filter(Boolean),
      outputs: (outputs || []).map((item) => String(item).trim()).filter(Boolean),
      processingTime: String(processingTime || '').trim(),
      description: String(description || '').trim()
    };
    if(processor.inputs.length === 0) throw new Error('At least one input is required');
    if(processor.outputs.length === 0) throw new Error('At least one output is required');
    return processor;
  }

  function toRow(processor){
    return { name: processor.name, inputs: processor.inputs, outputs: processor.outputs, processing_time: processor.processingTime || null, description: processor.description || null };
  }

  function fromRow(row){
    return normalizeProcessor(row.name, row.inputs || [], row.outputs || [], row.processing_time || '', row.description || '');
  }

  function rebuildMaps(system, processors){
    system.processors.clear();
    system.inputToProcessors.clear();
    system.outputToProcessors.clear();
    processors.forEach((processor) => {
      system.processors.set(processor.name, processor);
      processor.inputs.forEach((input) => {
        if(!system.inputToProcessors.has(input)) system.inputToProcessors.set(input, new Set());
        system.inputToProcessors.get(input).add(processor.name);
      });
      processor.outputs.forEach((output) => {
        if(!system.outputToProcessors.has(output)) system.outputToProcessors.set(output, new Set());
        system.outputToProcessors.get(output).add(processor.name);
      });
    });
  }

  async function loadProcessors(system){
    const { data, error } = await getClient().from(TABLE()).select('name, inputs, outputs, processing_time, description').order('name');
    if(error) throw new Error('Supabase load failed: ' + error.message);
    rebuildMaps(system, (data || []).map(fromRow));
    system.updateStats();
    return (data || []).length;
  }

  async function upsertProcessor(system, name, inputs, outputs, processingTime = '', description = ''){
    const processor = normalizeProcessor(name, inputs, outputs, processingTime, description);
    const { data, error } = await getClient().from(TABLE()).upsert(toRow(processor), { onConflict: 'name' }).select('name, inputs, outputs, processing_time, description').single();
    if(error) throw new Error('Supabase write failed: ' + error.message);
    const saved = fromRow(data);
    const next = Array.from(system.processors.values()).filter((item) => item.name !== saved.name);
    next.push(saved);
    rebuildMaps(system, next);
    system.updateStats();
    return saved;
  }

  async function deleteProcessor(system, name){
    if(!system.processors.has(name)) return false;
    const { error } = await getClient().from(TABLE()).delete().eq('name', name);
    if(error) throw new Error('Supabase delete failed: ' + error.message);
    rebuildMaps(system, Array.from(system.processors.values()).filter((item) => item.name !== name));
    system.updateStats();
    return true;
  }

  return { deleteProcessor, loadProcessors, upsertProcessor };
})();
