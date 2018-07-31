//
//  Queue.m
//  算法导论
//
//  Created by 温杰 on 2018/5/18.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Queue.h"

@interface Queue()
@property (nonatomic,strong) NSMutableArray * array;
@end

@implementation Queue

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.array = [NSMutableArray array];
    }
    return self;
}
-(void)enqueue:(id)object{
    [self.array addObject:object];
}
-(id)dequeue{
    if (self.array>0) {
        return self.array[0];
    }
    return nil;
}
@end
