import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";
function same(a: string, b: string) {return Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));}
export async function POST(request: NextRequest) {
  const origin=request.headers.get("origin");
  if(origin && new URL(origin).host !== request.headers.get("host"))return NextResponse.json({error:"Invalid origin"},{status:403});
  let token: unknown;
  try {
    const reader=request.body?.getReader(); if(!reader)throw Error();
    const chunks:Uint8Array[]=[];let bytes=0;
    while(true){const part=await reader.read();if(part.done)break;bytes+=part.value.byteLength;if(bytes>2048){await reader.cancel();return NextResponse.json({error:"Request too large"},{status:413})}chunks.push(part.value)}
    token=JSON.parse(Buffer.concat(chunks).toString("utf8")).token;
  } catch {return NextResponse.json({error:"Invalid request"},{status:400})}
  if(typeof token!=="string" || token.length>128)return NextResponse.json({error:"Invalid access token"},{status:401});
  const bootstrap=process.env.WORKSPACE_TOKEN;
  const owner=bootstrap && same(token,bootstrap);
  if(!owner){
    if(!/^surf_key_[a-f0-9]{64}$/.test(token))return NextResponse.json({error:"Invalid access token"},{status:401});
    try {const check=await fetch(`${process.env.API_URL ?? "http://127.0.0.1:8080"}/api/me`,{headers:{Authorization:`Bearer ${token}`},cache:"no-store",signal:AbortSignal.timeout(5000)});if(!check.ok)return NextResponse.json({error:"Access key is invalid, expired or revoked"},{status:401})}
    catch {return NextResponse.json({error:"Authentication service unavailable"},{status:503})}
  }
  const response=NextResponse.json({ok:true});
  response.cookies.set("surfacer_session",token,{httpOnly:true,sameSite:"strict",secure:request.nextUrl.protocol==="https:",path:"/",maxAge:28800});return response;
}
export async function DELETE(request: NextRequest){
 const origin=request.headers.get("origin");if(origin && new URL(origin).host!==request.headers.get("host"))return NextResponse.json({error:"Invalid origin"},{status:403});
 const response=NextResponse.json({ok:true});response.cookies.set("surfacer_session","",{httpOnly:true,sameSite:"strict",path:"/",maxAge:0});return response;
}
