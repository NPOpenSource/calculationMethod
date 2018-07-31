//
//  Heapify.h
//  算法导论
//
//  Created by 温杰 on 2018/5/11.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>

void heapSort(int *A,int length);

@interface Heapify : NSObject
-(void)maxHeapInsert:(int) key;
//-(void)heapIncreaseKey:(int)index :(int) key;
-(int )heapExtractMax;
-(int)heapMaxImum;
-(void)print;
@end
