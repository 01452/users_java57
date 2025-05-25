import { Injectable, NotFoundException } from '@nestjs/common';
import { User, UserDocument } from '../model/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from '../dto/CreateUserDto.dto';
import { UpdateUserDto } from '../dto/UpdateUserDto.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {
  }

  async create(dto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(dto.password, 10);
    return this.userModel.create(new this.userModel({ ...dto, password: hashedPassword }));
  }

  async getUserById(id: string) {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async removeUser(id: string) {
    const deleted = await this.userModel.findByIdAndDelete(id);
    if (!deleted) {
      throw new NotFoundException('User not found');
    }
    return deleted;
  }

  async updateUser(id: string, dto: UpdateUserDto) {
    const updated = await this.userModel.findByIdAndUpdate(id, dto);
    if (!updated) {
      throw new NotFoundException('User not found');
    }
    return updated;
  }

  getAllUser() {
    return this.userModel.find();
  }

  findByEmail(email: string) {
    return this.userModel.findOne({ email });
  }
}
