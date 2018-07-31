//
//  RadixSort.h
//  算法导论
//
//  Created by 温杰 on 2018/5/17.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>
void radixSort(int *A,int d,int length);
void radixSortBasecountingSort(int *A,int d,int length);

@interface RadixSort : NSObject
- (instancetype)initWithLength:(int)length;
-(void)append:(int)num;
-(void)writeData:(int *)m beginLocation:(int)beginIndex length:(int *)length;
-(void)clear;
@end
