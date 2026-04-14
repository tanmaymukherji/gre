const AppDataStore = (() => {
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

  function createSnapshot(system){
    return {
      processors: Array.from(system.processors.entries()),
      timestamp: new Date().toISOString(),
      version: '3.3'
    };
  }

  function seedBase(system){
    system.processors.clear();
    system.inputToProcessors.clear();
    system.outputToProcessors.clear();
    BASE_PROCESSORS.forEach(([name, inputs, outputs, processingTime, description]) => {
      system.addProcessor(name, inputs, outputs, processingTime, description);
    });
    saveToLocalStorage(system);
    system.updateStats();
  }

  function saveToLocalStorage(system){
    try{
      localStorage.setItem('productionChainData', JSON.stringify(createSnapshot(system)));
    }catch(error){
      console.warn('Could not save local working copy', error);
    }
  }

  function loadFromLocalStorage(system){
    try{
      const data = localStorage.getItem('productionChainData');
      if(!data) return false;
      const parsed = JSON.parse(data);
      if(parsed && Array.isArray(parsed.processors)){
        system.loadSnapshotIntoMaps(parsed);
        return true;
      }
    }catch(error){
      console.warn('Could not load local working copy', error);
    }
    return false;
  }

  function importSnapshot(system, data){
    if(!data || !Array.isArray(data.processors)) throw new Error('Invalid data format');
    system.processors.clear();
    system.inputToProcessors.clear();
    system.outputToProcessors.clear();
    data.processors.forEach(([name, processor]) => {
      if(processor) system.addProcessor(name, processor.inputs || [], processor.outputs || [], processor.processingTime || '', processor.description || '');
    });
    system.updateStats();
    saveToLocalStorage(system);
  }

  return {
    createSnapshot,
    importSnapshot,
    loadFromLocalStorage,
    saveToLocalStorage,
    seedBase
  };
})();
