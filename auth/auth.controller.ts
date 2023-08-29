import { Controller, Post, Body, Get, Param, Patch } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(@Body() createUserDto: CreateUserDto) {
    return this.authService.createUser(createUserDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Get('verify/:token')
  async verifyEmail(@Param('token') token: string) {
    return this.authService.verifyUser(token);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() body: { username: string }) {
    return this.authService.sendPasswordResetEmail(body.username);
  }

  @Patch('reset-password/:token')
  async resetPassword(@Param('token') token: string, @Body() body: { username: string, newPassword: string }) {
    return this.authService.resetPassword(body.username, body.newPassword, token);
  }

  @Get('details/:username')
  async getUserDetails(@Param('username') username: string) {
    return this.authService.getUserDetails(username);
  }

  @Patch('details/:username')
  async updateUserDetails(@Param('username') username: string, @Body() updates: UpdateUserDto) {
    return this.authService.updateUserDetails(username, updates);
  }

  
}
