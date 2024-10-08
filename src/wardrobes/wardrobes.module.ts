import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Wardrobes } from './entities/wardrobes.entity';
import { ClothingItem } from './entities/clothing_item.entity';
import { WardrobesController } from './controllers/wardrobes.controller';
import { WardrobeServices } from './services/wardrobes.services';
import { User } from 'src/user/entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Wardrobes, ClothingItem, User])],
  controllers: [WardrobesController],
  providers: [WardrobeServices],
})
export class WardrobesModule {}
