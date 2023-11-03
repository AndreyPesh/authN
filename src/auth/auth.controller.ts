import { Body, Controller, Get, Post } from '@nestjs/common';
import { LoginDto, RegisterDto } from './dto';

@Controller('auth')
export class AuthController {
    @Post('register')
    register(@Body() dto: RegisterDto) {}

    @Post('login')
    login(@Body() dto: LoginDto) {}

    @Get('refresh')
    refreshTokens() {}
}
