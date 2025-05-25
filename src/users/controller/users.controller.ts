import { Body, Controller, Delete, Get, Param, Post, Put, UseGuards } from '@nestjs/common';
import { UsersService } from '../service/users.service';
import { CreateUserDto } from '../dto/CreateUserDto.dto';
import { UpdateUserDto } from '../dto/UpdateUserDto.dto';
import { JwtAuthGuard } from '../../auth/jwt-auth.guard';

@Controller()
export class UsersController {
  constructor(private readonly appService: UsersService) {
  }

  @Post()
  createUser(@Body() dto: CreateUserDto) {
    return this.appService.create(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  getUser(@Param('id') id: string) {
    return this.appService.getUserById(id);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  getAllUser() {
    return this.appService.getAllUser();
  }

  @UseGuards(JwtAuthGuard)
  @Put(':id')
  updateUser(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    return this.appService.updateUser(id, dto);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  removeUser(@Param('id') id: string) {
    return this.appService.removeUser(id);
  }
}
