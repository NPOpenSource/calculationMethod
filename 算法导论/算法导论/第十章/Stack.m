//
//  Stack.m
//  算法导论
//
//  Created by 温杰 on 2018/5/18.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Stack.h"
@interface Stack()
@property (nonatomic,strong) NSMutableArray * array;
@end

@implementation Stack

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.array = [NSMutableArray array];
    }
    return self;
}

-(void)push:(id)object{
    [self.array addObject:object];
}
-(void)pop{
    [self.array removeLastObject];
}
-(BOOL)isEmpty{
    if (self.array.count==0) {
        return YES;
    }
    return NO;
}

@end
