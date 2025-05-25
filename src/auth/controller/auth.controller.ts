import { Body, Controller, Post } from '@nestjs/common';
import { LoginDto } from '../dto/login.dto';
import { AuthService } from '../service/authService.service';



@Controller()
export class AuthController{
  constructor(private authService: AuthService) {
  }

  @Post('login')
  login(@Body() dto:LoginDto){
      return this.authService.login(dto);
  }
}