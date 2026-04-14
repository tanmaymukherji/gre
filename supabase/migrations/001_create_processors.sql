create extension if not exists pgcrypto;

create table if not exists public.processors (
  name text primary key,
  inputs text[] not null default '{}',
  outputs text[] not null default '{}',
  processing_time text,
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint processors_inputs_nonempty check (cardinality(inputs) > 0),
  constraint processors_outputs_nonempty check (cardinality(outputs) > 0)
);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists processors_set_updated_at on public.processors;
create trigger processors_set_updated_at
before update on public.processors
for each row
execute function public.set_updated_at();

alter table public.processors enable row level security;

drop policy if exists "public can read processors" on public.processors;
create policy "public can read processors"
on public.processors
for select
to anon, authenticated
using (true);

drop policy if exists "public can insert processors" on public.processors;
create policy "public can insert processors"
on public.processors
for insert
to anon, authenticated
with check (true);

drop policy if exists "public can update processors" on public.processors;
create policy "public can update processors"
on public.processors
for update
to anon, authenticated
using (true)
with check (true);

drop policy if exists "public can delete processors" on public.processors;
create policy "public can delete processors"
on public.processors
for delete
to anon, authenticated
using (true);

insert into public.processors (name, inputs, outputs, processing_time, description) values
('Rice Mill', array['Paddy','Electricity','Water'], array['Rice','Rice Bran','Broken Rice','Rice Husk'], '2-4 hours', 'Processes harvested paddy into consumable rice'),
('Mustard Oil Mill', array['Mustard Seeds','Firewood'], array['Mustard Oil','Oil Cake'], '3-5 hours', 'Extracts oil from mustard seeds using traditional kolhu'),
('Coconut Oil Mill', array['Coconut','Firewood'], array['Coconut Oil','Coconut Cake','Coconut Shell'], '4-6 hours', 'Traditional oil extraction from coconuts'),
('Sugarcane Crusher', array['Sugarcane','Labor'], array['Sugarcane Juice','Bagasse'], '1-2 hours', 'Extracts juice from sugarcane stalks'),
('Jaggery Making Unit', array['Sugarcane Juice','Firewood'], array['Jaggery','Molasses'], '6-8 hours', 'Boils sugarcane juice to make jaggery'),
('Cotton Ginning Mill', array['Raw Cotton','Electricity'], array['Cotton Fiber','Cotton Seeds'], '2-3 hours', 'Separates cotton fibers from seeds'),
('Groundnut Decorticator', array['Groundnut Pods','Manual Labor'], array['Groundnut Kernels','Groundnut Shells'], '1-2 hours', 'Removes shells from groundnut pods'),
('Turmeric Processing Unit', array['Fresh Turmeric','Steam','Firewood'], array['Turmeric Powder','Turmeric Fingers'], '24-48 hours', 'Boils, dries and grinds turmeric'),
('Chili Processing Unit', array['Red Chilies','Sun','Manual Labor'], array['Chili Powder','Whole Dried Chilies'], '3-7 days', 'Dries and grinds red chilies'),
('Village Flour Mill', array['Wheat','Jowar','Bajra','Electricity'], array['Wheat Flour','Jowar Flour','Bajra Flour','Bran'], '1-2 hours', 'Grinds various grains into flour'),
('Dairy Cooperative', array['Buffalo Milk','Cow Milk','Refrigeration'], array['Butter','Ghee','Paneer','Buttermilk','Curd'], '4-12 hours', 'Processes milk into dairy products'),
('Poultry Farm', array['Chicken Feed','Water','Medicine','Chicks'], array['Eggs','Broiler Chicken','Chicken Manure'], '21 days eggs, 45 days broilers', 'Raises chickens for eggs and meat'),
('Goat Farm', array['Fodder','Water','Medicine','Goat Kids'], array['Goat Milk','Goat Meat','Goat Manure'], 'Daily milk, 6 months meat', 'Raises goats for milk and meat'),
('Fish Farm', array['Fish Seeds','Fish Feed','Water','Lime'], array['Fish','Fish Waste'], '6-12 months', 'Cultivates fish in ponds'),
('Sericulture Unit', array['Mulberry Leaves','Silkworm Eggs','Labor'], array['Silk Cocoons','Silk Yarn'], '25-30 days', 'Rears silkworms for silk production'),
('Bamboo Craft Unit', array['Bamboo','Tools','Skill'], array['Baskets','Mats','Furniture','Handicrafts'], '1-7 days', 'Creates products from bamboo'),
('Pottery Workshop', array['Clay','Water','Firewood','Tools'], array['Earthen Pots','Tiles','Decorative Items'], '2-3 days', 'Makes clay products'),
('Handloom Unit', array['Cotton Yarn','Silk Yarn','Dyes'], array['Khadi Cloth','Silk Sarees','Fabrics'], '1-30 days', 'Weaves textiles on traditional looms'),
('Vermicompost Unit', array['Organic Waste','Earthworms','Water'], array['Vermicompost','Liquid Fertilizer'], '45-60 days', 'Converts organic waste to fertilizer'),
('Biogas Plant', array['Cow Dung','Water','Organic Waste'], array['Biogas','Slurry'], 'Daily gas, 15-20 days slurry', 'Produces gas and fertilizer from organic matter'),
('Beekeeping Unit', array['Bee Colonies','Flowers','Hives'], array['Honey','Beeswax','Royal Jelly'], 'Seasonal', 'Maintains bee colonies for honey production'),
('Tamarind Processing', array['Tamarind Pods','Manual Labor'], array['Tamarind Pulp','Tamarind Seeds','Tamarind Shell'], '2-4 hours', 'Extracts pulp from tamarind pods'),
('Amla Processing', array['Fresh Amla','Salt','Turmeric'], array['Amla Pickle','Amla Juice','Dried Amla'], '7-15 days', 'Processes amla into various products'),
('Mahua Oil Mill', array['Mahua Seeds','Firewood'], array['Mahua Oil','Oil Cake'], '4-6 hours', 'Extracts oil from mahua seeds'),
('Lac Processing Unit', array['Lac Insects','Host Trees'], array['Shellac','Lac Dye'], '6 months', 'Harvests and processes lac from insects'),
('Village Blacksmith', array['Iron','Coal','Tools','Fire'], array['Agricultural Tools','Household Items'], '2-8 hours', 'Forges metal tools and implements'),
('Leather Tanning Unit', array['Raw Hides','Tanning Agents','Water'], array['Tanned Leather','Leather Products'], '7-15 days', 'Processes animal hides into leather'),
('Rope Making Unit', array['Coconut Coir','Hemp','Jute'], array['Ropes','Mats','Brushes'], '2-6 hours', 'Makes ropes from natural fibers'),
('Pickle Making Unit', array['Vegetables','Oil','Spices','Salt'], array['Various Pickles'], '15-30 days', 'Preserves vegetables in oil and spices'),
('Papad Making Unit', array['Lentil Flour','Spices','Water'], array['Papads','Vadiyam'], '1-2 days', 'Makes dried lentil wafers')
on conflict (name) do update
set
  inputs = excluded.inputs,
  outputs = excluded.outputs,
  processing_time = excluded.processing_time,
  description = excluded.description,
  updated_at = now();
