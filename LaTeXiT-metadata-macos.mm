// Copyright (c) 2021 Pierre Chatelier
//
//SPDX-License-Identifier: Zlib

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <zlib.h>

#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <Quartz/Quartz.h>

static int DebugLogLevel = 0;//increase for verbosity
#define DebugLog(level,log,...) do{if (DebugLogLevel>=level) {NSLog(@"[%p : %@ %s] \"%@\"",[NSThread currentThread],[self class],sel_getName(_cmd),[NSString stringWithFormat:log,##__VA_ARGS__]);}}while(0)
#define DebugLogStatic(level,log,...) do{if (DebugLogLevel>=level) {NSLog(@"[%p - static] \"%@\"",[NSThread currentThread], [NSString stringWithFormat:log,##__VA_ARGS__]);}}while(0)

static unsigned int EndianUI_BtoN(unsigned int x)
{
  return (sizeof(x) == sizeof(uint32_t)) ? EndianU32_BtoN(x) :
         (sizeof(x) == sizeof(uint64_t)) ? EndianU64_BtoN(x) :
         x;
}
static unsigned int bigToHost(unsigned int x) {return EndianUI_BtoN(x);}

enum {
  RKLNoOptions             = 0,
  RKLCaseless              = 2,
  RKLComments              = 4,
  RKLDotAll                = 32,
  RKLMultiline             = 8,
  RKLUnicodeWordBoundaries = 256
};
typedef uint32_t RKLRegexOptions;

static NSRegularExpressionOptions convertRKLOptions(RKLRegexOptions options)
{
  NSRegularExpressionOptions result = 0;
  if ((options & RKLCaseless) != 0)
    result |= NSRegularExpressionCaseInsensitive;
  if ((options & RKLComments) != 0)
    result |= NSRegularExpressionAllowCommentsAndWhitespace;
  if ((options & RKLDotAll) != 0)
    result |= NSRegularExpressionDotMatchesLineSeparators;
  if ((options & RKLMultiline) != 0)
    result |= NSRegularExpressionAnchorsMatchLines;
  if ((options & RKLUnicodeWordBoundaries) != 0)
    result |= NSRegularExpressionUseUnicodeWordBoundaries;
  return result;
}
//end convertRKLOptions()

@interface NSObject (Extended)

+(Class) dynamicCastToClass:(Class)aClass;
-(id) dynamicCastToClass:(Class)aClass;
@end

@implementation NSObject (Extended)

+(Class) dynamicCastToClass:(Class)aClass
{
  Class result = ![self isSubclassOfClass:aClass] ? nil : aClass;
  return result;
}
//end dynamicCastToClass:

-(id) dynamicCastToClass:(Class)aClass
{
  id result = ![self isKindOfClass:aClass] ? nil : self;
  return result;
}
//end dynamicCastToClass:

@end

@interface NSString (Extended)

-(NSRange) range;
-(BOOL) isMatchedByRegex:(NSString*)pattern;
-(BOOL) isMatchedByRegex:(NSString*)pattern options:(RKLRegexOptions)options inRange:(NSRange)range error:(NSError**)error;
-(NSArray*) captureComponentsMatchedByRegex:(NSString*)pattern options:(RKLRegexOptions)options range:(NSRange)range error:(NSError**)error;

@end

@implementation NSString (Extended)

-(NSRange) range
{
  return NSMakeRange(0, self.length);
}
//end range

-(BOOL) isMatchedByRegex:(NSString*)pattern
{
  BOOL result = [self isMatchedByRegex:pattern options:0 inRange:self.range error:nil];
  return result;
}
//end isMatchedByRegex:

-(BOOL) isMatchedByRegex:(NSString*)pattern options:(RKLRegexOptions)options inRange:(NSRange)range error:(NSError**)error
{
  BOOL result = false;
  NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:pattern options:convertRKLOptions(options) error:error];
  result = ([regex numberOfMatchesInString:self options:0 range:range] > 0);
  return result;
}
//end isMatchedByRegex:options:inRange:error:

-(NSArray*) captureComponentsMatchedByRegex:(NSString*)pattern options:(RKLRegexOptions)options range:(NSRange)range error:(NSError**)error
{
  NSMutableArray* result = nil;
  NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:pattern options:convertRKLOptions(options) error:error];
  NSTextCheckingResult* match = [regex firstMatchInString:self options:0 range:range];
  result = [NSMutableArray arrayWithCapacity:match.numberOfRanges];
  for(NSUInteger i = 0, count = match.numberOfRanges ; i<count ; ++i)
  {
    NSRange matchRange = [match rangeAtIndex:i];
    NSString* captureComponent = (matchRange.location == NSNotFound) ? @"" : [self substringWithRange:matchRange];
    if (captureComponent != nil)
      [result addObject:captureComponent];
  }//end for each match
  return [[result copy] autorelease];
}
//end componentsMatchedByRegex:options:range:error:

@end

@interface NSData (Extended)

+(id) dataWithBase64:(NSString*)base64;
+(id) dataWithBase64:(NSString*)base64 encodedWithNewlines:(BOOL)encodedWithNewlines;
-(NSString*) encodeBase64;
-(NSString*) encodeBase64WithNewlines:(BOOL)encodeWithNewlines;
-(NSString*) sha1Base64;

@end

@implementation NSData (Extended)

+(id) dataWithBase64:(NSString*)base64
{
  return [self dataWithBase64:base64 encodedWithNewlines:YES];
}
//end initWithBase64:

+(id) dataWithBase64:(NSString*)base64 encodedWithNewlines:(BOOL)encodedWithNewlines
{
  #if OPENSSL_AVAILABLE
  NSMutableData* result = [NSMutableData data];
  const char* utf8String = [base64 UTF8String];
  NSUInteger utf8Length = [base64 lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  BIO* mem = BIO_new_mem_buf((void*)utf8String, utf8Length);
  BIO* b64 = BIO_new(BIO_f_base64());
  if (!encodedWithNewlines)
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, mem);

  // Decode into an NSMutableData
  char inbuf[512] = {0};
  int inlen = 0;
  while ((inlen = BIO_read(b64, inbuf, MIN(utf8Length, sizeof(inbuf)))) > 0)
    [result appendBytes:inbuf length:inlen];
    
  //Clean up and go home
  BIO_free_all(b64);
  #else
  NSData* result = nil;
  if ([[NSData class] instancesRespondToSelector:@selector(initWithBase64EncodedString:options:)])
   result = [[[NSData alloc] initWithBase64EncodedString:base64 options:(encodedWithNewlines ? (NSDataBase64Encoding64CharacterLineLength|NSDataBase64EncodingEndLineWithLineFeed) : 0)] autorelease];
  #endif
  return result;
}
//end dataWithBase64:encodedWithNewlines:

-(NSString*) encodeBase64
{
  NSString* result = [self encodeBase64WithNewlines:YES];
  return result;
}
//end encodeBase64

-(NSString*) encodeBase64WithNewlines:(BOOL)encodeWithNewlines
{
  NSString* result = nil;
  #if OPENSSL_AVAILABLE
  BIO* mem = BIO_new(BIO_s_mem());
  BIO* b64 = BIO_new(BIO_f_base64());
  if (!encodeWithNewlines)
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  mem = BIO_push(b64, mem);
  BIO_write(mem, [self bytes], [self length]);
  int error = BIO_flush(mem);
  if (error != 1)
    DebugLog(0, @"BIO_flush : %d", error);
  char* base64Pointer = 0;
  long base64Length = BIO_get_mem_data(mem, &base64Pointer);
  #ifdef ARC_ENABLED
  result = [[NSString alloc] initWithBytes:base64Pointer length:base64Length encoding:NSUTF8StringEncoding];
  #else
  result = [[[NSString alloc] initWithBytes:base64Pointer length:base64Length encoding:NSUTF8StringEncoding] autorelease];
  #endif
  BIO_free_all(mem);
  #else
  if ([self respondsToSelector:@selector(base64EncodedStringWithOptions:)])
   result = [self base64EncodedStringWithOptions:(encodeWithNewlines ? (NSDataBase64Encoding64CharacterLineLength|NSDataBase64EncodingEndLineWithLineFeed) : 0)];
  #endif
  return result;
}
//end encodeBase64WithNewlines:

-(NSString*) sha1Base64
{
  NSString* result = nil;
  #if OPENSSL_AVAILABLE
  unsigned char sha[SHA_DIGEST_LENGTH] = {0};
  SHA1([self bytes], [self length], sha);
  NSData* wrapper = [[NSData alloc] initWithBytesNoCopy:sha length:SHA_DIGEST_LENGTH freeWhenDone:NO];
  result = [wrapper encodeBase64WithNewlines:NO];
  #ifdef ARC_ENABLED
  #else
  [wrapper release];
  #endif
  #else
  unsigned char digest[CC_SHA1_DIGEST_LENGTH] = {0};
  if (CC_SHA1([self bytes], (int)[self length], digest))
  {
    NSData* wrapper = [[NSData alloc] initWithBytesNoCopy:digest length:CC_SHA1_DIGEST_LENGTH freeWhenDone:NO];
    result = [wrapper encodeBase64WithNewlines:NO];
    #ifdef ARC_ENABLED
    #else
    [wrapper release];
    #endif
  }//end if (CC_SHA1([self bytes], [self length], digest))
  #endif
  return result;
}
//end sha1Base64

@end

@interface Compressor : NSObject {
}
+(NSData*) zipuncompress:(NSData*)data;
@end

@implementation Compressor

+(NSData*) zipuncompress:(NSData*)data
{
  NSData* result = nil;
  if (data)
  {
    unsigned int bigDestLen = 0;
    [data getBytes:&bigDestLen length:sizeof(unsigned int)];
    unsigned int destLen = EndianUI_BtoN(bigDestLen);
    uLongf destLenf = destLen;
    NSMutableData* decompData = [[NSMutableData alloc] initWithLength:destLen];
    int error = uncompress((unsigned char*)[decompData mutableBytes], &destLenf,
                           (const unsigned char*)[data bytes]+sizeof(unsigned int), [data length]-sizeof(unsigned int));
    switch(error)
    {
      case Z_OK:
        result = [decompData copy];
        break;
      case Z_DATA_ERROR:
        DebugLog(0, @"Error while decompressing data : data seems corrupted");
        break;
      default:
        DebugLog(0, @"Error while decompressing data : Insufficient memory" );
        DebugLog(0, @"destLen = %u", destLen);
        DebugLog(0, @"destLenf = %u", (unsigned int)destLenf);
        DebugLog(0, @"error = %d", error);
        break;
    }//end switch(error)
    [decompData release];
  }//end if (data)
  [result autorelease];
  return result;
}
//end zipuncompress:

@end

@interface LaTeXiTMetaDataParsingContext : NSObject
{
  BOOL latexitMetadataStarted;
  NSMutableString* latexitMetadataString;
  id latexitMetadata;
  CGPoint* curvePoints;
  size_t curvePointsCapacity;
  size_t curvePointsSize;
}

-(BOOL) latexitMetadataStarted;
-(void) setLatexitMetadataStarted:(BOOL)value;
-(NSMutableString*) latexitMetadataString;
-(id) latexitMetadata;
-(void) setLatexitMetadata:(id)plist;
-(void) resetCurvePoints;
-(void) appendCurvePoint:(CGPoint)point;
-(void) checkMetadataFromCurvePointBytes;
-(void) checkMetadataFromString:(NSString*)string;

@end //LaTeXiTMetaDataParsingContext

@implementation LaTeXiTMetaDataParsingContext

-(id) init
{
  if (!((self = [super init])))
    return nil;
  self->latexitMetadataStarted = NO;
  self->latexitMetadataString = [[NSMutableString alloc] init];
  self->latexitMetadata = nil;
  self->curvePoints = 0;
  self->curvePointsCapacity = 0;
  self->curvePointsSize = 0;
  return self;
}
//end init

-(void) dealloc
{
  [self->latexitMetadataString release];
  [self->latexitMetadata release];
  if (self->curvePoints)
    free(self->curvePoints);
  [super dealloc];
}
//end dealloc

-(BOOL) latexitMetadataStarted
{
  return self->latexitMetadataStarted;
}
//end latexitMetadataStarted

-(void) setLatexitMetadataStarted:(BOOL)value
{
  self->latexitMetadataStarted = value;
}
//end setLatexitMetadataStarted:

-(NSMutableString*) latexitMetadataString
{
  return self->latexitMetadataString;
}
//end latexitMetadataString

-(id) latexitMetadata
{
  return [[self->latexitMetadata retain] autorelease];
}
//end latexitMetadata

-(void) setLatexitMetadata:(id)plist
{
  if (plist != self->latexitMetadata)
  {
    [self->latexitMetadata release];
    self->latexitMetadata = [plist retain];
  }//end if (plist != self->latexitMedatata)
}
//end setLatexitMetadata

-(void) resetCurvePoints
{
  self->curvePointsSize = 0;
}
//end resetCurvePoints:

-(void) appendCurvePoint:(CGPoint)point
{
  DebugLog(1, @"(%.20f,%.20f)", point.x, point.y);
  if (self->curvePointsSize+1 > self->curvePointsCapacity)
  {
    size_t newCapacity = MAX(64U, 2*self->curvePointsCapacity);
    self->curvePoints = (CGPoint*)reallocf(self->curvePoints, newCapacity*sizeof(CGPoint));
    self->curvePointsCapacity = !self->curvePoints ? 0 : newCapacity;
    self->curvePointsSize = MIN(self->curvePointsSize, self->curvePointsCapacity);
  }//end if (self->curvePointsSize+1 > self->curvePointsCapacity)
  if (self->curvePointsSize+1 <= self->curvePointsCapacity)
    self->curvePoints[self->curvePointsSize++] = point;
}
//end appendCurvePoint:

-(void) checkMetadataFromCurvePointBytes
{
  NSMutableString* candidateString = nil;
  const CGPoint* src = self->curvePoints;
  const CGPoint* srcEnd = self->curvePoints+self->curvePointsSize;
  double epsilon = 1e-6;
  for( ; src != srcEnd ; ++src)
  {
    BOOL isIntegerX = (ABS(src->x-floor(src->x)) <= epsilon);
    BOOL isValidIntegerX = isIntegerX && (src->x >= 0) && (src->x <= 255);
    BOOL isIntegerY = (ABS(src->y-floor(src->y)) <= epsilon);
    BOOL isValidIntegerY = isIntegerY && (src->y >= 0) && (src->y <= 255);
    if (isValidIntegerX && isValidIntegerY)
    {
      candidateString = !candidateString ? [[NSMutableString alloc] init] : candidateString;
      [candidateString appendFormat:@"%c%c", (char)(unsigned char)src->x, (char)(unsigned char)src->y];
    }//end if (isValidIntegerX && isValidIntegerY)
  }//end for each point
  [self checkMetadataFromString:candidateString];
  [candidateString release];
}
//end checkMetadataFromCurvePointBytes

-(void) checkMetadataFromString:(NSString*)string
{
  NSError* error = nil;
  NSArray* components =
    [string captureComponentsMatchedByRegex:@"^\\<latexit sha1_base64=\"(.*?)\"\\>(.*?)\\</latexit\\>\\x00*$"
                                    options:RKLMultiline|RKLDotAll
                                      range:string.range error:&error];
  if ([components count] == 3)
  {
    DebugLogStatic(1, @"this is metadata : %@", string);
    NSString* sha1Base64 = [components objectAtIndex:1];
    NSString* dataBase64Encoded = [components objectAtIndex:2];
    NSString* dataBase64EncodedSha1Base64 = [[dataBase64Encoded dataUsingEncoding:NSUTF8StringEncoding] sha1Base64];
    NSData* compressedData = [sha1Base64 isEqualToString:dataBase64EncodedSha1Base64] ?
      [NSData dataWithBase64:dataBase64Encoded encodedWithNewlines:NO] :
      nil;
    NSData* uncompressedData = !compressedData ? nil : [Compressor zipuncompress:compressedData];
    NSPropertyListFormat format = NSPropertyListBinaryFormat_v1_0;
    id plist = !uncompressedData ? nil :
      [NSPropertyListSerialization propertyListWithData:uncompressedData
        options:NSPropertyListImmutable format:&format error:nil];
    NSDictionary* plistAsDictionary = [plist dynamicCastToClass:[NSDictionary class]];
    if (plistAsDictionary)
      [self setLatexitMetadata:plistAsDictionary];
  }//end if ([components count] == 3)
}
//end checkMetadataFromString:

@end //LaTeXiTMetaDataParsingContext

static void CHCGPDFOperatorCallback_b(CGPDFScannerRef scanner, void *info)
{
  //closepath,fill,stroke
  DebugLogStatic(1, @"<b (closepath,fill,stroke)>");
}
//end CHCGPDFOperatorCallback_b()

static void CHCGPDFOperatorCallback_bstar(CGPDFScannerRef scanner, void *info)
{
  //closepath, fill, stroke (EO)
  DebugLogStatic(1, @"<b* (closepath, fill, stroke) (EO)>");
}
//end CHCGPDFOperatorCallback_bstar()

static void CHCGPDFOperatorCallback_B(CGPDFScannerRef scanner, void *info)
{
  //fill, stroke
  DebugLogStatic(1, @"<B (fill,stroke)>");
}
//end CHCGPDFOperatorCallback_B()

static void CHCGPDFOperatorCallback_Bstar(CGPDFScannerRef scanner, void *info)
{
  //fill, stroke (EO)
  DebugLogStatic(1, @"<B* (closepath, fill, stroke) (EO)>");
}
//end CHCGPDFOperatorCallback_Bstar()

static void CHCGPDFOperatorCallback_c(CGPDFScannerRef scanner, void *info)
{
  //curveto (3 points)
  DebugLogStatic(1, @"<c (curveto)>");
  LaTeXiTMetaDataParsingContext* pdfScanningContext = [(id)info dynamicCastToClass:[LaTeXiTMetaDataParsingContext class]];
  CGPDFReal valueNumber1 = 0;
  CGPDFReal valueNumber2 = 0;
  CGPDFReal valueNumber3 = 0;
  CGPDFReal valueNumber4 = 0;
  CGPDFReal valueNumber5 = 0;
  CGPDFReal valueNumber6 = 0;
  BOOL ok = YES;
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber6);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber5);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber4);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber3);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber2);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber1);
  [pdfScanningContext appendCurvePoint:CGPointMake(valueNumber1, valueNumber2)];
  [pdfScanningContext appendCurvePoint:CGPointMake(valueNumber3, valueNumber4)];
  [pdfScanningContext appendCurvePoint:CGPointMake(valueNumber5, valueNumber6)];
}
//end CHCGPDFOperatorCallback_c()

static void CHCGPDFOperatorCallback_cs(CGPDFScannerRef scanner, void *info)
{
  //set color space (for non stroking)
  DebugLogStatic(1, @"<cs (set color space (for non stroking)>,");
}
//end CHCGPDFOperatorCallback_cs()

static void CHCGPDFOperatorCallback_h(CGPDFScannerRef scanner, void *info)
{
  //close subpath
  DebugLogStatic(1, @"<h (close subpath)>");
  LaTeXiTMetaDataParsingContext* pdfScanningContext = [(id)info dynamicCastToClass:[LaTeXiTMetaDataParsingContext class]];
  [pdfScanningContext checkMetadataFromCurvePointBytes];
  [pdfScanningContext resetCurvePoints];
}
//end CHCGPDFOperatorCallback_h()

static void CHCGPDFOperatorCallback_l(CGPDFScannerRef scanner, void *info)
{
  //lineto (1 point)
  LaTeXiTMetaDataParsingContext* pdfScanningContext = [(id)info dynamicCastToClass:[LaTeXiTMetaDataParsingContext class]];
  DebugLogStatic(1, @"<l (lineto)>");
  CGPDFReal valueNumber1 = 0;
  CGPDFReal valueNumber2 = 0;
  BOOL ok = YES;
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber2);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber1);
  [pdfScanningContext appendCurvePoint:CGPointMake(valueNumber1, valueNumber2)];
}
//end CHCGPDFOperatorCallback_l()

static void CHCGPDFOperatorCallback_m(CGPDFScannerRef scanner, void *info)
{
  //moveto (new subpath)
  DebugLogStatic(1, @"<m (moveto) (new subpath)>");
  LaTeXiTMetaDataParsingContext* pdfScanningContext = [(id)info dynamicCastToClass:[LaTeXiTMetaDataParsingContext class]];
  [pdfScanningContext resetCurvePoints];
}
//end CHCGPDFOperatorCallback_m()

static void CHCGPDFOperatorCallback_n(CGPDFScannerRef scanner, void *info)
{
  //end path (no fill, no stroke)
  DebugLogStatic(1, @"<n end path (no fill, no stroke)>");
}
//end CHCGPDFOperatorCallback_n()

static void CHCGPDFOperatorCallback_Tj(CGPDFScannerRef scanner, void *info)
{
  CGPDFStringRef pdfString = 0;
  BOOL okString = CGPDFScannerPopString(scanner, &pdfString);
  if (okString)
  {
    CFStringRef cfString = CGPDFStringCopyTextString(pdfString);
    #ifdef ARC_ENABLED
    NSString* string = (CHBRIDGE NSString*)cfString;
    #else
    NSString* string = [(NSString*)cfString autorelease];
    #endif
    DebugLogStatic(1, @"PDF scanning found <%@>", string);
    
    LaTeXiTMetaDataParsingContext* pdfScanningContext = [(id)info dynamicCastToClass:[LaTeXiTMetaDataParsingContext class]];

    BOOL isStartingLatexitMetadata = [string isMatchedByRegex:@"^\\<latexit sha1_base64=\""];
    if (isStartingLatexitMetadata)
    {
      [pdfScanningContext setLatexitMetadataStarted:YES];
      [[pdfScanningContext latexitMetadataString] setString:@""];
    }//end if (isStartingLatexitMetadata)

    BOOL isLatexitMetadataStarted = [pdfScanningContext latexitMetadataStarted];
    NSMutableString* latexitMedatataString = [pdfScanningContext latexitMetadataString];

    if (isLatexitMetadataStarted)
      [latexitMedatataString appendString:string];
    
    BOOL isStoppingLatexitMetadata = isLatexitMetadataStarted && [string isMatchedByRegex:@"\\</latexit\\>$"];
    if (isStoppingLatexitMetadata)
      [pdfScanningContext setLatexitMetadataStarted:NO];

    NSString* stringToMatch = latexitMedatataString;
    [pdfScanningContext checkMetadataFromString:stringToMatch];
  }//end if (okString)
}//end CHCGPDFOperatorCallback_Tj

static void CHCGPDFOperatorCallback_v(CGPDFScannerRef scanner, void *info)
{
  //curve
  DebugLogStatic(1, @"<v (curve)>");
  LaTeXiTMetaDataParsingContext* pdfScanningContext = [(id)info dynamicCastToClass:[LaTeXiTMetaDataParsingContext class]];
  CGPDFReal valueNumber1 = 0;
  CGPDFReal valueNumber2 = 0;
  CGPDFReal valueNumber3 = 0;
  CGPDFReal valueNumber4 = 0;
  BOOL ok = YES;
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber4);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber3);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber2);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber1);
  [pdfScanningContext appendCurvePoint:CGPointMake(valueNumber1, valueNumber2)];
  [pdfScanningContext appendCurvePoint:CGPointMake(valueNumber3, valueNumber4)];
}
//end CHCGPDFOperatorCallback_v()

static void CHCGPDFOperatorCallback_y(CGPDFScannerRef scanner, void *info)
{
  //curveto
  DebugLogStatic(1, @"<y (curveto)>");
  CGPDFReal valueNumber1 = 0;
  CGPDFReal valueNumber2 = 0;
  CGPDFReal valueNumber3 = 0;
  CGPDFReal valueNumber4 = 0;
  BOOL ok = YES;
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber4);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber3);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber2);
  ok = ok && CGPDFScannerPopNumber(scanner, &valueNumber1);
}
//end CHCGPDFOperatorCallback_y()

template<typename T>
static inline std::ostream& operator<<(std::ostream& stream, const std::vector<T>& v)
{
  for(const auto& it : v)
    printf("%x:", (int)it);
  return stream;
}
//end operator<<(std::ostream&, const std::vector<T>&)

std::vector<unsigned char> extractPDF(const char* filename)
{
  std::vector<unsigned char> result;

  std::vector<unsigned char> data;
  std::FILE* fp = !filename ? 0 : std::fopen(filename, "rb");
  if (fp)
  {
    std::fseek(fp, 0, SEEK_END);
    const size_t size = ftell(fp);
    data.resize(size);
    std::fseek(fp, 0, SEEK_SET);
    if (!data.empty())
      std::fread(data.data(), sizeof(unsigned char), size, fp);
    std::fclose(fp);
  }//end if (fp)
  
  const std::string beginTokenString = "%PDF";
  const std::string endTokenString = "%EOF\n";
  const std::vector<unsigned char> beginToken(beginTokenString.cbegin(), beginTokenString.cend());
  const std::vector<unsigned char> endToken(endTokenString.cbegin(), endTokenString.cend());
  const auto it1 = std::search(data.cbegin(), data.cend(), beginToken.cbegin(), beginToken.cend());
  const auto it2 = std::search(it1, data.cend(), endToken.cbegin(), endToken.cend());
  if (it2 != data.cend())
    result = std::vector<unsigned char>(it1, it2+endToken.size());
  return result;
}
//end extractPDF()

std::vector<unsigned char> zipuncompress(const std::vector<unsigned char>& data)
{
  std::vector<unsigned char> result;
  if (data.size() >= 4)
  {
    unsigned int bigDestLen = 0;
    memcpy(&bigDestLen, data.data(), 4);
    unsigned int destLen = bigToHost(bigDestLen);
    uLongf destLenf = destLen;
    result.resize(destLen);
    int error = uncompress(result.data(), &destLenf, data.data()+4, data.size()-4);
    switch(error)
    {
      case Z_OK:
        break;
      case Z_DATA_ERROR:
        break;
      default:
        break;
    }//end switch(error)
  }//end if (data.size() >= 4)
  return result;
}
//end zipuncompress:

void usage(int argc, char* argv[])
{
  std::cout << "Usage : " << argv[0] << " " << "<filename.pdf|filename.emf>" << std::endl;
}
//end usage()

int main(int argc, char* argv[])
{
  int result = 0;

  if (argc < 2)
  {
    usage(argc, argv);
    result = -1;
  }//end if (argc < 2)
  else//if (argc >= 2)
  {
    @autoreleasepool {
      const char* filename = argv[1];
      std::cout << "extracting PDF data from <" << filename << ">" << std::endl;
      std::vector<unsigned char> pdfData = extractPDF(filename);
      std::cout << "pdfData size : " << pdfData.size() << std::endl;
      
      CFDataRef someData = pdfData.empty() ? 0 : CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, pdfData.data(), pdfData.size(), 0);
      CGDataProviderRef dataProvider = !someData ? 0 : CGDataProviderCreateWithCFData((CFDataRef)someData);
      CGPDFDocumentRef pdfDocument = !dataProvider ? 0 :
      CGPDFDocumentCreateWithProvider(dataProvider);
      CGPDFPageRef page = !pdfDocument || !CGPDFDocumentGetNumberOfPages(pdfDocument) ? 0 : CGPDFDocumentGetPage(pdfDocument, 1);
      CGPDFDictionaryRef pageDictionary = !page ? 0 : CGPDFPageGetDictionary(page);
    
      NSDictionary* latexitMetadata = nil;
      CGPDFContentStreamRef contentStream = !page ? 0 : CGPDFContentStreamCreateWithPage(page);
      CGPDFOperatorTableRef operatorTable = CGPDFOperatorTableCreate();
      CGPDFOperatorTableSetCallback(operatorTable, "b", &CHCGPDFOperatorCallback_b);
      CGPDFOperatorTableSetCallback(operatorTable, "b*", &CHCGPDFOperatorCallback_bstar);
      CGPDFOperatorTableSetCallback(operatorTable, "B", &CHCGPDFOperatorCallback_B);
      CGPDFOperatorTableSetCallback(operatorTable, "B*", &CHCGPDFOperatorCallback_Bstar);
      CGPDFOperatorTableSetCallback(operatorTable, "c", &CHCGPDFOperatorCallback_c);
      CGPDFOperatorTableSetCallback(operatorTable, "cs", &CHCGPDFOperatorCallback_cs);
      CGPDFOperatorTableSetCallback(operatorTable, "h", &CHCGPDFOperatorCallback_h);
      CGPDFOperatorTableSetCallback(operatorTable, "l", &CHCGPDFOperatorCallback_l);
      CGPDFOperatorTableSetCallback(operatorTable, "m", &CHCGPDFOperatorCallback_m);
      CGPDFOperatorTableSetCallback(operatorTable, "n", &CHCGPDFOperatorCallback_n);
      CGPDFOperatorTableSetCallback(operatorTable, "Tj", &CHCGPDFOperatorCallback_Tj);
      CGPDFOperatorTableSetCallback(operatorTable, "v", &CHCGPDFOperatorCallback_v);
      CGPDFOperatorTableSetCallback(operatorTable, "y", &CHCGPDFOperatorCallback_y);
      LaTeXiTMetaDataParsingContext* pdfScanningContext = [[LaTeXiTMetaDataParsingContext alloc] init];
      CGPDFScannerRef pdfScanner = !contentStream ? 0 : CGPDFScannerCreate(contentStream, operatorTable, pdfScanningContext);
      CGPDFScannerScan(pdfScanner);
      CGPDFScannerRelease(pdfScanner);
      CGPDFOperatorTableRelease(operatorTable);
      CGPDFContentStreamRelease(contentStream);
      if (someData)
        CFRelease(someData);
      latexitMetadata = [[pdfScanningContext latexitMetadata] dynamicCastToClass:[NSDictionary class]];
      latexitMetadata = [latexitMetadata copy];
      [latexitMetadata autorelease];
      [pdfScanningContext release];

      std::stringstream texStream;
      size_t metadataIndex = 0;
      if (latexitMetadata != nil)
      {
        NSString* preamble = [[latexitMetadata objectForKey:@"preamble"] dynamicCastToClass:[NSString class]];
        NSString* source = [[latexitMetadata objectForKey:@"source"] dynamicCastToClass:[NSString class]];
        id mode = nil;
        if (!mode)
          mode = [[latexitMetadata objectForKey:@"type"] dynamicCastToClass:[NSNumber class]];
        if (!mode)
          mode = [[latexitMetadata objectForKey:@"type"] dynamicCastToClass:[NSString class]];
        if (!mode)
          mode = [[latexitMetadata objectForKey:@"mode"] dynamicCastToClass:[NSNumber class]];
        if (!mode)
          mode = [[latexitMetadata objectForKey:@"mode"] dynamicCastToClass:[NSString class]];
        if (preamble != nil)
	{
	  std::string preambleString;
	  preambleString = [preamble UTF8String];
          texStream << preambleString << std::endl;
	  std::string extraPreamble;
	  extraPreamble = "\\pagestyle{empty}";
	  if (preambleString.find(extraPreamble) == std::string::npos)
	  {
            texStream << extraPreamble << std::endl;
	  }
	}
        if (source != nil)
        {
          std::string prefix;
          std::string suffix;
          if (mode != nil)
          {
            int modeInt = [mode intValue];
            if (modeInt == 0)//DISPLAY
            {
              prefix = "\\[";
              suffix = "\\]";
            }//end if (modeInt == 0)
            else if (modeInt == 1)//INLINE
            {
              prefix = "$";
              suffix = "$";
            }//end if (modeInt == 1)
            else if (modeInt == 2) {//TEXT
            }//end if (modeInt == 2)
            else if (modeInt == 3)//EQNARRAY
            {
              prefix = "\\begin{eqnarray*}";
              suffix = "\\end{eqnarray*}";
            }//end if (modeInt == 3)
            else if (modeInt == 4)//ALIGN
            {
              prefix = "\\begin{align*}";
              suffix = "\\end{align*}";
            }//end if (modeInt == 4)
          }//end if (mode != nil)
          texStream << "\\begin{document}" << std::endl;
          texStream << prefix << [source UTF8String] << suffix << std::endl;
          texStream << "\\end{document}" << std::endl;
        }//end if (source != nil)
      }//end if (dict != nil)
      std::string texString = texStream.str();
      std::cout << "full TeX : " << texString << std::endl;
      if (!texString.empty())
      {
        std::string texFileName = std::string(filename)+(!metadataIndex ? "" : ("-"+std::to_string(metadataIndex)))+".tex";
        std::FILE* fTex = std::fopen(texFileName.c_str(), "wb");
        if (fTex)
        {
          std::fwrite(texString.c_str(), sizeof(unsigned char), texString.size(), fTex);
          std::cout << "written to " << texFileName << std::endl;
          std::fclose(fTex);
        }//end if (fTex)
      }//end if (!texString.empty())
      ++metadataIndex;
    }//end @autoreleasepool
  }//end if (argc >= 2)
  return result;
}
//end main()
