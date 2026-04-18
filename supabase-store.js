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
    const { data, error } = await getClient().from(TABLE()).select('id, name, inputs, outputs, processing_time, description, status').eq('status', 'approved').order('name');
    if(error) throw new Error('Supabase load failed: ' + error.message);
    rebuildMaps(system, (data || []).map(fromRow));
    system.updateStats();
    return (data || []).length;
  }

  async function submitProcessor(name, inputs, outputs, processingTime = '', description = ''){
    const processor = normalizeProcessor(name, inputs, outputs, processingTime, description);
    const payload = {
      ...toRow(processor),
      status: 'pending',
      approved_at: null,
      approved_by: null
    };
    const { error } = await getClient().from(TABLE()).insert(payload);
    if(error){
      if(error.code === '23505') throw new Error('A processor with this name already exists or is already waiting for approval');
      throw new Error('Supabase write failed: ' + error.message);
    }
    return processor;
  }

  return { loadProcessors, submitProcessor };
})();
