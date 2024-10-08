import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt.auth.gards';
import { WardrobeServices } from '../services/wardrobes.services';
import { WardrobeDto } from '../dtos/create-ward.dto';
import { CreateClothingItemDto } from '../dtos/create_clothing.dto';

@ApiTags('Wardrobe')
@Controller('wardrobe')
export class WardrobesController {
  constructor(private readonly wardServices: WardrobeServices) {}

  @UseGuards(JwtAuthGuard)
  @Get('/me')
  async countMenus(@Req() req: Request) {
    const userID = req['user']['userId'];
    return this.wardServices.findAllWardsByUser(userID);
  }

  @Get('/bydining/:id')
  async getMenuByDining(@Param('id') id: string) {
    return this.wardServices.findClothingItemsByWardId(id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/create/')
  async createMenuwithItem(@Req() req: Request, @Body() ward: WardrobeDto) {
    const userID = req['user']['userId'];
    return this.wardServices.createWardrobe(ward, userID);
  }

  @UseGuards(JwtAuthGuard)
  @Put('/edit/')
  async editMenuwithItem(@Req() req: Request, @Body() ward: WardrobeDto) {
    const userID = req['user']['userId'];
    return this.wardServices.editWardrobeByUser(ward, userID);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('/delete/')
  async deleteWardrobem(@Req() req: Request, @Body() ward: WardrobeDto) {
    const userID = req['user']['userId'];
    return this.wardServices.deleteWardrobeByUser(ward.id, userID);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/add-item/')
  async additemWardrobe(@Body() ward: CreateClothingItemDto) {
    return this.wardServices.addWardItemByMenuID(ward);
  }
}
