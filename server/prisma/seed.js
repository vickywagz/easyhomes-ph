import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
const prisma = new PrismaClient();

async function main() {
  const passwordHash = await bcrypt.hash('DemoPassword!ChangeMe2026', 12);
  const landlord = await prisma.user.upsert({
    where: { email: 'demo.landlord@easyhomes.local' },
    update: {},
    create: { fullName: 'Demo Property Contact', email: 'demo.landlord@easyhomes.local', phone: '+2348000000000', passwordHash, role: 'LANDLORD' }
  });
  const properties = [
    { title: 'Bright 2-Bedroom Flat in Rumuola', description: 'A practical two-bedroom flat in a residential compound. Confirm current rent, fees, water arrangements, power pattern and availability directly before paying or booking.', area: 'Rumuola', propertyType: 'Flat', rentNaira: 1800000, bedrooms: 2, bathrooms: 2, amenities: ['Parking','Water storage','Tiled floors'], imageUrls: ['https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?auto=format&fit=crop&w=1200&q=80'] },
    { title: 'Family Duplex in Woji', description: 'A family-sized duplex in a residential area of Woji. Ask for a current inspection, a full written fee breakdown and confirmation of utility arrangements before making a payment.', area: 'Woji', propertyType: 'Duplex', rentNaira: 3500000, bedrooms: 3, bathrooms: 3, amenities: ['Parking','Compound','Fenced property'], imageUrls: ['https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=1200&q=80'] },
    { title: 'Compact 1-Bedroom Apartment in Ada George', description: 'A compact one-bedroom option for someone looking for a simpler home. Verify the exact street, transport access, utility supply and all move-in charges during inspection.', area: 'Ada George', propertyType: 'Apartment', rentNaira: 950000, bedrooms: 1, bathrooms: 1, amenities: ['Water storage','Secure gate'], imageUrls: ['https://images.unsplash.com/photo-1600210492486-724fe5c67fb0?auto=format&fit=crop&w=1200&q=80'] },
    { title: '3-Bedroom Flat in Rukpokwu', description: 'A three-bedroom listing for comparison purposes. Availability, rent, exact address, property photographs and advertiser authority must be checked before this sample is approved for public use.', area: 'Rukpokwu', propertyType: 'Flat', rentNaira: 1500000, bedrooms: 3, bathrooms: 2, amenities: ['Parking','Water storage'], imageUrls: ['https://images.unsplash.com/photo-1600566753086-00f18fb6b3ea?auto=format&fit=crop&w=1200&q=80'] }
  ];
  for (const item of properties) {
    await prisma.property.upsert({
      where: { id: `demo-${item.area.toLowerCase().replaceAll(' ','-')}` },
      update: {},
      create: { id: `demo-${item.area.toLowerCase().replaceAll(' ','-')}`, ...item, landlordId: landlord.id, status: 'APPROVED', verification: 'UNVERIFIED', lastConfirmedAt: new Date() }
    }).catch(async () => {
      const exists = await prisma.property.findFirst({ where: { title: item.title } });
      if (!exists) await prisma.property.create({ data: { ...item, landlordId: landlord.id, status: 'APPROVED', verification: 'UNVERIFIED', lastConfirmedAt: new Date() } });
    });
  }
  console.log('Seed complete. Demo landlord:', landlord.email);
  console.log('Demo password is for local development only; change or remove it before deployment.');
}
main().finally(() => prisma.$disconnect());
