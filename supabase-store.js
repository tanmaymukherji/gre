const AppDataStore = (() => {
  const TABLE = () => (window.APP_CONFIG && window.APP_CONFIG.SUPABASE_TABLE) || 'processors';
  let client = null;

  const BASE_PROCESSORS = [
    ['Rice Mill', ['Paddy','Electricity','Water'], ['Rice','Rice Bran','Broken Rice','Rice Husk'], '2-4 hours', 'Processes harvested paddy into consumable rice'],
    ['Mustard Oil Mill', ['Mustard Seeds','Firewood'], ['Mustard Oil','Oil Cake'], '3-5 hours', 'Extracts oil from mustard seeds using traditional kolhu'],
    ['Coconut Oil Mill', ['Coconut','Firewood'], ['Coconut Oil','Coconut Cake','Coconut Shell'], '4-6 hours', 'Traditional oil extraction from coconuts'],
    ['Sugarcane Crusher', ['Sugarcane','Labor'], ['Sugarcane Juice','Bagasse'], '1-2 hours', 'Extracts juice from sugarcane stalks'],
    ['Jaggery Making Unit', ['Sugarcane Juice','Firewood'], ['Jaggery','Molasses'], '6-8 hours', 'Boils sugarcane juice to make jaggery'],
    ['Cotton Ginning Mill', ['Raw Cotton','Electricity'], ['Cotton Fiber','Cotton Seeds'], '2-3 hours', 'Separates cotton fibers from seeds'],
    ['Groundnut Decorticator', ['Groundnut Pods','Manual Labor'], ['Groundnut Kernels','Groundnut Shells'], '1-2 hours', 'Removes shells from groundnut pods'],
    ['Turmeric Processing Unit', ['Fresh Turmeric','Steam','Firewood'], ['Turmeric Powder','Turmeric Fingers'], '24-48 hours', 'Boils, dries and grinds turmeric'],
    ['Chili Processing Unit', ['Red Chilies','Sun','Manual Labor'], ['Chili Powder','Whole Dried Chilies'], '3-7 days', 'Dries and grinds red chilies'],
    ['Village Flour Mill', ['Wheat','Jowar','Bajra','Electricity'], ['Wheat Flour','Jowar Flour','Bajra Flour','Bran'], '1-2 hours', 'Grinds various grains into flour'],
    ['Dairy Cooperative', ['Buffalo Milk','Cow Milk','Refrigeration'], ['Butter','Ghee','Paneer','Buttermilk','Curd'], '4-12 hours', 'Processes milk into dairy products'],
    ['Poultry Farm', ['Chicken Feed','Water','Medicine','Chicks'], ['Eggs','Broiler Chicken','Chicken Manure'], '21 days eggs, 45 days broilers', 'Raises chickens for eggs and meat'],
    ['Goat Farm', ['Fodder','Water','Medicine','Goat Kids'], ['Goat Milk','Goat Meat','Goat Manure'], 'Daily milk, 6 months meat', 'Raises goats for milk and meat'],
    ['Fish Farm', ['Fish Seeds','Fish Feed','Water','Lime'], ['Fish','Fish Waste'], '6-12 months', 'Cultivates fish in ponds'],
    ['Sericulture Unit', ['Mulberry Leaves','Silkworm Eggs','Labor'], ['Silk Cocoons','Silk Yarn'], '25-30 days', 'Rears silkworms for silk production'],
    ['Bamboo Craft Unit', ['Bamboo','Tools','Skill'], ['Baskets','Mats','Furniture','Handicrafts'], '1-7 days', 'Creates products from bamboo'],
    ['Pottery Workshop', ['Clay','Water','Firewood','Tools'], ['Earthen Pots','Tiles','Decorative Items'], '2-3 days', 'Makes clay products'],
    ['Handloom Unit', ['Cotton Yarn','Silk Yarn','Dyes'], ['Khadi Cloth','Silk Sarees','Fabrics'], '1-30 days', 'Weaves textiles on traditional looms'],
    ['Vermicompost Unit', ['Organic Waste','Earthworms','Water'], ['Vermicompost','Liquid Fertilizer'], '45-60 days', 'Converts organic waste to fertilizer'],
    ['Biogas Plant', ['Cow Dung','Water','Organic Waste'], ['Biogas','Slurry'], 'Daily gas, 15-20 days slurry', 'Produces gas and fertilizer from organic matter'],
    ['Beekeeping Unit', ['Bee Colonies','Flowers','Hives'], ['Honey','Beeswax','Royal Jelly'], 'Seasonal', 'Maintains bee colonies for honey production'],
    ['Tamarind Processing', ['Tamarind Pods','Manual Labor'], ['Tamarind Pulp','Tamarind Seeds','Tamarind Shell'], '2-4 hours', 'Extracts pulp from tamarind pods'],
    ['Amla Processing', ['Fresh Amla','Salt','Turmeric'], ['Amla Pickle','Amla Juice','Dried Amla'], '7-15 days', 'Processes amla into various products'],
    ['Mahua Oil Mill', ['Mahua Seeds','Firewood'], ['Mahua Oil','Oil Cake'], '4-6 hours', 'Extracts oil from mahua seeds'],
    ['Lac Processing Unit', ['Lac Insects','Host Trees'], ['Shellac','Lac Dye'], '6 months', 'Harvests and processes lac from insects'],
    ['Village Blacksmith', ['Iron','Coal','Tools','Fire'], ['Agricultural Tools','Household Items'], '2-8 hours', 'Forges metal tools and implements'],
    ['Leather Tanning Unit', ['Raw Hides','Tanning Agents','Water'], ['Tanned Leather','Leather Products'], '7-15 days', 'Processes animal hides into leather'],
    ['Rope Making Unit', ['Coconut Coir','Hemp','Jute'], ['Ropes','Mats','Brushes'], '2-6 hours', 'Makes ropes from natural fibers'],
    ['Pickle Making Unit', ['Vegetables','Oil','Spices','Salt'], ['Various Pickles'], '15-30 days', 'Preserves vegetables in oil and spices'],
    ['Papad Making Unit', ['Lentil Flour','Spices','Water'], ['Papads','Vadiyam'], '1-2 days', 'Makes dried lentil wafers']
  ];

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

  function createSnapshot(system){
    return { processors: Array.from(system.processors.entries()), timestamp: new Date().toISOString(), version: '3.4' };
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

  async function replaceAll(system, processors){
    const normalized = processors.map((processor) => normalizeProcessor(processor.name, processor.inputs, processor.outputs, processor.processingTime, processor.description));
    const { error: deleteError } = await getClient().from(TABLE()).delete().not('name', 'is', null);
    if(deleteError) throw new Error('Supabase reset failed: ' + deleteError.message);
    if(normalized.length > 0){
      const { error: insertError } = await getClient().from(TABLE()).insert(normalized.map(toRow));
      if(insertError) throw new Error('Supabase bulk insert failed: ' + insertError.message);
    }
    rebuildMaps(system, normalized);
    system.updateStats();
  }

  async function seedBase(system){
    await replaceAll(system, BASE_PROCESSORS.map(([name, inputs, outputs, processingTime, description]) => ({ name, inputs, outputs, processingTime, description })));
  }

  async function importSnapshot(system, data){
    if(!data || !Array.isArray(data.processors)) throw new Error('Invalid data format');
    await replaceAll(system, data.processors.map(([name, processor]) => ({ name, inputs: processor.inputs || [], outputs: processor.outputs || [], processingTime: processor.processingTime || '', description: processor.description || '' })));
  }

  return { createSnapshot, deleteProcessor, importSnapshot, loadProcessors, seedBase, upsertProcessor };
})();
