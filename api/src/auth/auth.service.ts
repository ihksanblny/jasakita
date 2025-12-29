import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PrismaService } from "../../prisma/prisma.service";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
    ) {}

    async login(email: string, password: string) {
        const user = await this.prisma.user.findUnique({
            where:{ email },
        });

        if (!user) {
            throw new UnauthorizedException('Email atau Password Salah');
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            throw new UnauthorizedException('Email atau Password Salah');
        }

        const payload = {
            sub: user.id,
            email: user.email,
            role: user.role, // string: 'ADMIN' | 'CUSTOMER'
        };

        return {
            access_token: this.jwtService.sign(payload),
        };
    }
}